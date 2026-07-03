use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use clap::Parser;
use log::{error, info, warn};

use spooky_config::runtime::RuntimeConfig;
use spooky_config::validator::validate as validate_config;
use spooky_edge::types::RuntimeBundleHandle;
use spooky_edge::{QUICListener, configure_async_runtime};

use crate::listener_group::{
    ListenerGroupRuntime, collect_finished_listener_groups, log_listener_startup,
    reconcile_listener_groups, spawn_managed_listener_group,
};
use crate::privilege_drop;
use crate::runtime_guard;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    config: Option<String>,
}

pub(crate) fn main_entry() {
    let cli = Cli::parse();

    const DEFAULT_CONFIG_PATH: &str = "/etc/spooky/config.yaml";
    let config_path = match cli.config {
        Some(path) => path,
        None if Path::new(DEFAULT_CONFIG_PATH).exists() => DEFAULT_CONFIG_PATH.to_string(),
        None => {
            fatal_startup_error(
                &format!(
                    "no --config provided and default config '{}' was not found.",
                    DEFAULT_CONFIG_PATH
                ),
                false,
                2,
            );
        }
    };

    let config_yaml = match spooky_config::loader::read_config(&config_path) {
        Ok(cfg) => cfg,
        Err(err_msg) => {
            fatal_startup_error(&format!("loading config failed: {}", err_msg), false, 1);
        }
    };

    spooky_utils::logger::init_logger(
        &config_yaml.log.level,
        config_yaml.log.file.enabled,
        &config_yaml.log.file.path,
        config_yaml.log.format == spooky_config::config::LogFormat::Json,
    );
    spooky_utils::telemetry::init_tracing(
        config_yaml.observability.tracing.enabled,
        &config_yaml.observability.tracing.service_name,
        config_yaml.observability.tracing.otlp_endpoint.as_deref(),
        config_yaml.observability.tracing.sample_ratio,
    );
    runtime_guard::install_panic_hook();

    let uid = unsafe { libc::getuid() };

    if let Err(err) = validate_config(&config_yaml) {
        fatal_startup_error(&format!("Configuration validation failed: {err}"), true, 1);
    }

    let runtime_config = match RuntimeConfig::from_config(&config_yaml) {
        Ok(config) => config,
        Err(err) => {
            fatal_startup_error(
                &format!("Runtime configuration normalization failed: {err}"),
                true,
                1,
            );
        }
    };

    if uid != 0
        && runtime_config
            .listeners
            .iter()
            .any(|listener| listener.listen.port < 1024)
    {
        fatal_startup_error(
            "binding a privileged port requires root or CAP_NET_BIND_SERVICE. Use ports >= 1024 for unprivileged startup.",
            true,
            1,
        );
    }

    let control_plane_threads = runtime_config.performance.control_plane_threads.max(1);
    configure_async_runtime(control_plane_threads);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(control_plane_threads)
        .thread_name("spooky-control-plane")
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            fatal_startup_error(
                &format!(
                    "Failed to initialize Tokio control-plane runtime (threads={}): {}",
                    control_plane_threads, err
                ),
                true,
                1,
            );
        }
    };

    runtime.block_on(run(
        runtime_config,
        config_yaml.log.clone(),
        uid,
        config_path,
    ));
}

async fn run(
    runtime_config: RuntimeConfig,
    log_config: spooky_config::config::Log,
    uid: libc::uid_t,
    config_path: String,
) {
    let runtime_bundle =
        match QUICListener::build_runtime_bundle(config_path, log_config, &runtime_config) {
            Ok(bundle) => bundle,
            Err(e) => {
                error!("Failed to initialize shared runtime state: {}", e);
                std::process::exit(1);
            }
        };
    let shared_state = Arc::clone(&runtime_bundle.shared_state);
    let runtime_bundle = Arc::new(RuntimeBundleHandle::new(runtime_bundle));

    let worker_count = runtime_config.performance.worker_threads.max(1);
    let shard_count = runtime_config.performance.packet_shards_per_worker.max(1);
    let effective_worker_count = worker_count.saturating_mul(shard_count);
    if let Err(err) = QUICListener::spawn_control_plane_tasks_with_runtime_bundle(
        &runtime_config,
        &shared_state,
        Arc::clone(&runtime_bundle),
        effective_worker_count,
    ) {
        error!("Failed to initialize control-plane tasks: {}", err);
        std::process::exit(1);
    }

    let binds_privileged_port = runtime_config
        .listeners
        .iter()
        .any(|listener| listener.listen.port < 1024);
    if uid != 0 && binds_privileged_port {
        fatal_startup_error(
            "binding a privileged port requires root or CAP_NET_BIND_SERVICE. Use ports >= 1024 for unprivileged startup.",
            true,
            1,
        );
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_flag = shutdown.clone();
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        shutdown_flag.store(true, Ordering::Relaxed);
    });

    let mut listener_groups = Vec::new();
    let mut next_worker_index_base = 0usize;
    for listener_config in runtime_config.listener_runtime_configs() {
        match spawn_managed_listener_group(
            listener_config,
            Arc::clone(&shared_state),
            Arc::clone(&runtime_bundle),
            next_worker_index_base,
        ) {
            Ok(group) => {
                next_worker_index_base =
                    next_worker_index_base.saturating_add(group.signature.worker_count);
                listener_groups.push(group);
            }
            Err(err) => {
                error!("{}", err);
                std::process::exit(1);
            }
        }
    }

    log_listener_startup(&runtime_config, &listener_groups);
    apply_privilege_drop(uid, &runtime_config);

    let mut worker_failed = false;
    while !shutdown.load(Ordering::Relaxed) {
        collect_finished_listener_groups(&mut listener_groups, &mut worker_failed);
        reconcile_listener_groups(
            &runtime_bundle,
            &mut listener_groups,
            &mut next_worker_index_base,
        );

        if worker_failed {
            break;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    shutdown_listener_groups(&mut listener_groups, &mut worker_failed).await;

    let panic_count = runtime_guard::panic_count();
    if panic_count > 0 {
        worker_failed = true;
        error!("Process captured {} panic(s) via panic hook", panic_count);
    }

    if worker_failed {
        spooky_utils::telemetry::shutdown_tracing();
        std::process::exit(1);
    }
    spooky_utils::telemetry::shutdown_tracing();
    info!("Spooky shutdown complete");
}

async fn shutdown_listener_groups(
    listener_groups: &mut Vec<ListenerGroupRuntime>,
    worker_failed: &mut bool,
) {
    for group in listener_groups.iter() {
        group.request_shutdown();
    }
    loop {
        collect_finished_listener_groups(listener_groups, worker_failed);
        if listener_groups.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    for group in listener_groups.drain(..) {
        group.join_all(worker_failed);
    }
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    match signal(SignalKind::terminate()) {
        Ok(mut sigterm) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        }
        Err(err) => {
            warn!(
                "Failed to register SIGTERM handler ({}); falling back to Ctrl+C only",
                err
            );
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn fatal_startup_error(message: &str, logger_ready: bool, exit_code: i32) -> ! {
    if logger_ready {
        error!("{}", message);
    } else {
        eprintln!("Error: {}", message);
    }
    std::process::exit(exit_code);
}

fn apply_privilege_drop(uid: libc::uid_t, runtime_config: &RuntimeConfig) {
    if uid != 0 || !runtime_config.security.privileges.enabled {
        return;
    }

    let user = runtime_config.security.privileges.user.trim();
    let group = runtime_config.security.privileges.group.trim();
    match privilege_drop::drop_privileges(user, group) {
        Ok(()) => {
            info!(
                "Dropped process privileges to user='{}' group='{}'",
                user, group
            );
        }
        Err(err) => {
            fatal_startup_error(
                &format!(
                    "Failed to drop process privileges to user='{}' group='{}': {}",
                    user, group, err
                ),
                true,
                1,
            );
        }
    }
}
