//! Spooky HTTP/3 Load Balancer - Main Entry Point

use std::net::SocketAddr;
use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
mod privilege_drop;
mod runtime_guard;

use spooky_config::runtime::{ListenerRuntimeConfig, RuntimeConfig};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::{thread, time::Duration};

use clap::Parser;
use log::{error, info, warn};

use spooky_config::validator::validate as validate_config;
use spooky_edge::types::RuntimeBundleHandle;
use spooky_edge::{
    QUICListener, SharedRuntimeState, configure_async_runtime, constants::MAX_DATAGRAM_SIZE_BYTES,
    stable_hash_socket_addr,
};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    // Path to the configuration file.
    #[arg(short, long)]
    config: Option<String>,
}

struct IngressPacket {
    peer: SocketAddr,
    local_addr: SocketAddr,
    bytes: Vec<u8>,
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

fn main() {
    // Parse CLI arguments
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

    // Read configuration file
    let config_yaml = match spooky_config::loader::read_config(&config_path) {
        Ok(cfg) => cfg,
        Err(err_msg) => {
            fatal_startup_error(&format!("loading config failed: {}", err_msg), false, 1);
        }
    };

    // Initialize the Logger
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

    // Validate Configurations
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

    runtime.block_on(run(runtime_config, uid, config_path));
}

async fn run(runtime_config: RuntimeConfig, uid: libc::uid_t, config_path: String) {
    let runtime_bundle = match QUICListener::build_runtime_bundle(config_path, &runtime_config) {
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

    let pin_workers = runtime_config.performance.pin_workers;
    let shard_queue_capacity = runtime_config
        .performance
        .packet_shard_queue_capacity
        .max(1);
    let shard_queue_max_bytes = runtime_config
        .performance
        .packet_shard_queue_max_bytes
        .max(1);
    let mut worker_handles: Vec<thread::JoinHandle<Result<(), String>>> = Vec::new();
    let mut worker_index_base = 0usize;

    for listener_config in runtime_config.listener_runtime_configs() {
        if let Err(err) = QUICListener::spawn_bootstrap_tls_listener(
            &listener_config,
            &shared_state,
            Some(Arc::clone(&runtime_bundle)),
        ) {
            error!(
                "Failed to initialize bootstrap TLS listener {} ({}:{}): {}",
                listener_config.listen.index,
                listener_config.listen.listen.address,
                listener_config.listen.listen.port,
                err
            );
            std::process::exit(1);
        }

        match spawn_listener_worker_group(
            listener_config,
            worker_count,
            shard_count,
            shard_queue_capacity,
            shard_queue_max_bytes,
            pin_workers,
            Arc::clone(&shared_state),
            Arc::clone(&runtime_bundle),
            Arc::clone(&shutdown),
            worker_index_base,
        ) {
            Ok(handles) => worker_handles.extend(handles),
            Err(err) => {
                error!("{}", err);
                std::process::exit(1);
            }
        }

        worker_index_base = worker_index_base.saturating_add(worker_count.max(1));
    }

    info!("Spooky is starting");
    info!(
        "Ingress listeners={} packet_shards_per_worker={} reuseport={} pin_workers={}",
        runtime_config.listeners.len(),
        shard_count,
        runtime_config.performance.reuseport,
        runtime_config.performance.pin_workers
    );
    for listener in &runtime_config.listeners {
        info!(
            "Listener {}: HTTP/3 (QUIC) on UDP {}:{}, HTTP/1.1+HTTP/2 bootstrap (TLS) on TCP {}:{} with Alt-Svc upgrade",
            listener.index,
            listener.listen.address,
            listener.listen.port,
            listener.listen.address,
            listener.listen.port,
        );
    }
    info!(
        "Data-plane workers={} packet_shards_per_worker={} reuseport={} pin_workers={}",
        worker_handles.len(),
        shard_count,
        runtime_config.performance.reuseport,
        runtime_config.performance.pin_workers
    );

    let mut worker_failed = false;
    let mut active_worker_handles = worker_handles;
    while !shutdown.load(Ordering::Relaxed) {
        let mut idx = 0usize;
        while idx < active_worker_handles.len() {
            if !active_worker_handles[idx].is_finished() {
                idx += 1;
                continue;
            }

            let handle = active_worker_handles.swap_remove(idx);
            join_worker_handle(handle, &mut worker_failed);
            if worker_failed {
                shutdown.store(true, Ordering::Relaxed);
                break;
            }
        }

        if worker_failed {
            break;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    for handle in active_worker_handles {
        join_worker_handle(handle, &mut worker_failed);
    }

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

#[allow(clippy::too_many_arguments)]
fn spawn_listener_worker_group(
    listener_config: ListenerRuntimeConfig,
    worker_count: usize,
    shard_count: usize,
    shard_queue_capacity: usize,
    shard_queue_max_bytes: usize,
    pin_workers: bool,
    worker_shared: Arc<SharedRuntimeState>,
    runtime_bundle: Arc<RuntimeBundleHandle>,
    worker_shutdown: Arc<AtomicBool>,
    worker_index_base: usize,
) -> Result<Vec<thread::JoinHandle<Result<(), String>>>, String> {
    let sockets = if worker_count > 1 {
        match QUICListener::bind_reuseport_sockets(&listener_config, worker_count) {
            Ok(sockets) => sockets,
            Err(e) => return Err(format!("Failed to bind SO_REUSEPORT sockets: {}", e)),
        }
    } else {
        match QUICListener::bind_socket(&listener_config, false) {
            Ok(socket) => vec![socket],
            Err(e) => return Err(format!("Failed to bind UDP socket: {}", e)),
        }
    };

    let mut worker_handles = Vec::with_capacity(sockets.len());
    for (socket_idx, socket) in sockets.into_iter().enumerate() {
        let worker_idx = worker_index_base.saturating_add(socket_idx);
        let worker_config = listener_config.clone();
        let worker_shutdown = Arc::clone(&worker_shutdown);
        let worker_shared = Arc::clone(&worker_shared);
        let worker_runtime_bundle = Arc::clone(&runtime_bundle);
        let thread_name = format!("spooky-data-plane-{}", worker_idx);
        let handle =
            thread::Builder::new()
                .name(thread_name)
                .spawn(move || -> Result<(), String> {
                    if shard_count <= 1 {
                        return run_single_listener_worker(
                            worker_idx,
                            pin_workers,
                            worker_config,
                            socket,
                            worker_shared,
                            Arc::clone(&worker_runtime_bundle),
                            worker_shutdown,
                        );
                    }

                    run_sharded_listener_worker(
                        worker_idx,
                        shard_count,
                        shard_queue_capacity,
                        shard_queue_max_bytes,
                        pin_workers,
                        worker_config,
                        socket,
                        worker_shared,
                        Arc::clone(&worker_runtime_bundle),
                        worker_shutdown,
                    )
                });

        match handle {
            Ok(handle) => worker_handles.push(handle),
            Err(err) => {
                return Err(format!(
                    "Failed to spawn worker thread {}: {}",
                    worker_idx, err
                ));
            }
        }
    }

    Ok(worker_handles)
}

#[allow(clippy::too_many_arguments)]
fn run_sharded_listener_worker(
    worker_idx: usize,
    shard_count: usize,
    shard_queue_capacity: usize,
    shard_queue_max_bytes: usize,
    pin_workers: bool,
    worker_config: ListenerRuntimeConfig,
    socket: std::net::UdpSocket,
    worker_shared: Arc<SharedRuntimeState>,
    runtime_bundle: Arc<RuntimeBundleHandle>,
    worker_shutdown: Arc<AtomicBool>,
) -> Result<(), String> {
    maybe_pin_worker(worker_idx, pin_workers);
    let dispatcher_slot = worker_idx.saturating_mul(shard_count);
    worker_shared.bind_metrics_worker_slot(dispatcher_slot);

    let local_addr = socket
        .local_addr()
        .map_err(|err| format!("worker {} local_addr failed: {}", worker_idx, err))?;

    let mut shard_handles = Vec::with_capacity(shard_count);
    let mut shard_txs: Vec<SyncSender<IngressPacket>> = Vec::with_capacity(shard_count);
    let mut shard_queue_bytes: Vec<Arc<AtomicUsize>> = Vec::with_capacity(shard_count);

    for shard_idx in 0..shard_count {
        let shard_socket = socket.try_clone().map_err(|err| {
            format!(
                "worker {} shard {} socket clone failed: {}",
                worker_idx, shard_idx, err
            )
        })?;
        let shard_config = worker_config.clone();
        let shard_shared = Arc::clone(&worker_shared);
        let shard_shutdown = Arc::clone(&worker_shutdown);
        let shard_thread_idx = worker_idx
            .saturating_mul(shard_count)
            .saturating_add(shard_idx);
        let shard_queue_bytes_counter = Arc::new(AtomicUsize::new(0));
        shard_queue_bytes.push(Arc::clone(&shard_queue_bytes_counter));

        let (tx, rx) = mpsc::sync_channel::<IngressPacket>(shard_queue_capacity);
        shard_txs.push(tx);
        let shard_runtime_bundle = Arc::clone(&runtime_bundle);

        let shard_name = format!("spooky-data-plane-{}-shard-{}", worker_idx, shard_idx);
        let shard_handle = thread::Builder::new()
            .name(shard_name)
            .spawn(move || -> Result<(), String> {
                maybe_pin_worker(shard_thread_idx, pin_workers);
                shard_shared.bind_metrics_worker_slot(shard_thread_idx);
                let mut listener = QUICListener::new_with_socket_and_shared_state(
                    shard_config,
                    shard_socket,
                    shard_shared,
                )
                .map_err(|err| {
                    format!(
                        "worker {} shard {} listener init failed: {}",
                        worker_idx, shard_idx, err
                    )
                })?
                .with_runtime_bundle(Arc::clone(&shard_runtime_bundle));

                let idle_timeout = Duration::from_millis(10);
                while !shard_shutdown.load(Ordering::Relaxed) {
                    match rx.recv_timeout(idle_timeout) {
                        Ok(mut packet) => {
                            let packet_bytes = packet.bytes.len();
                            listener.process_datagram(
                                packet.peer,
                                packet.local_addr,
                                &mut packet.bytes,
                            );
                            release_shard_queue_bytes(
                                shard_queue_bytes_counter.as_ref(),
                                packet_bytes,
                            );
                        }
                        Err(RecvTimeoutError::Timeout) => {
                            listener.poll_idle();
                        }
                        Err(RecvTimeoutError::Disconnected) => {
                            break;
                        }
                    }
                }

                listener.start_draining();
                while !listener.drain_complete() {
                    listener.poll_idle();
                }
                Ok(())
            })
            .map_err(|err| {
                format!(
                    "failed to spawn worker {} shard {}: {}",
                    worker_idx, shard_idx, err
                )
            })?;
        shard_handles.push(shard_handle);
    }

    let mut recv_buf = [0u8; MAX_DATAGRAM_SIZE_BYTES];
    while !worker_shutdown.load(Ordering::Relaxed) {
        match socket.recv_from(&mut recv_buf) {
            Ok((len, peer)) => {
                if len == 0 {
                    continue;
                }
                let shard_idx = shard_index_for_peer(&peer, shard_count);
                let packet_len = len;
                if !try_reserve_shard_queue_bytes(
                    shard_queue_bytes[shard_idx].as_ref(),
                    packet_len,
                    shard_queue_max_bytes,
                ) {
                    worker_shared.inc_ingress_queue_drop();
                    worker_shared.inc_ingress_queue_drop_bytes(packet_len);
                    let total: usize = shard_queue_bytes
                        .iter()
                        .map(|c| c.load(Ordering::Relaxed))
                        .sum();
                    worker_shared.set_ingress_queue_bytes(total);
                    continue;
                }
                let packet = IngressPacket {
                    peer,
                    local_addr,
                    bytes: recv_buf[..len].to_vec(),
                };
                match shard_txs[shard_idx].try_send(packet) {
                    Ok(()) => {
                        let total: usize = shard_queue_bytes
                            .iter()
                            .map(|c| c.load(Ordering::Relaxed))
                            .sum();
                        worker_shared.set_ingress_queue_bytes(total);
                    }
                    Err(TrySendError::Full(packet)) => {
                        release_shard_queue_bytes(
                            shard_queue_bytes[shard_idx].as_ref(),
                            packet.bytes.len(),
                        );
                        worker_shared.inc_ingress_queue_drop();
                        worker_shared.inc_ingress_queue_drop_bytes(packet.bytes.len());
                        let total: usize = shard_queue_bytes
                            .iter()
                            .map(|c| c.load(Ordering::Relaxed))
                            .sum();
                        worker_shared.set_ingress_queue_bytes(total);
                    }
                    Err(TrySendError::Disconnected(packet)) => {
                        release_shard_queue_bytes(
                            shard_queue_bytes[shard_idx].as_ref(),
                            packet.bytes.len(),
                        );
                        return Err(format!(
                            "worker {} shard {} dispatch channel disconnected",
                            worker_idx, shard_idx
                        ));
                    }
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(err) => {
                return Err(format!(
                    "worker {} ingress recv failed: {}",
                    worker_idx, err
                ));
            }
        }
    }

    drop(shard_txs);

    let mut shard_failed = false;
    for handle in shard_handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                shard_failed = true;
                error!("Worker {} shard exited with error: {}", worker_idx, err);
            }
            Err(_) => {
                shard_failed = true;
                error!("Worker {} shard thread panicked", worker_idx);
            }
        }
    }
    if shard_failed {
        Err(format!("worker {} had failing shard(s)", worker_idx))
    } else {
        Ok(())
    }
}

fn run_single_listener_worker(
    worker_idx: usize,
    pin_workers: bool,
    worker_config: ListenerRuntimeConfig,
    socket: std::net::UdpSocket,
    worker_shared: Arc<SharedRuntimeState>,
    runtime_bundle: Arc<RuntimeBundleHandle>,
    worker_shutdown: Arc<AtomicBool>,
) -> Result<(), String> {
    maybe_pin_worker(worker_idx, pin_workers);
    worker_shared.bind_metrics_worker_slot(worker_idx);
    let mut listener =
        QUICListener::new_with_socket_and_shared_state(worker_config, socket, worker_shared)
            .map_err(|err| format!("worker {} listener init failed: {}", worker_idx, err))?
            .with_runtime_bundle(Arc::clone(&runtime_bundle));

    while !worker_shutdown.load(Ordering::Relaxed) {
        listener.poll();
    }

    listener.start_draining();
    while !listener.drain_complete() {
        listener.poll();
    }
    Ok(())
}

fn shard_index_for_peer(peer: &SocketAddr, shard_count: usize) -> usize {
    (stable_hash_socket_addr(peer) as usize) % shard_count.max(1)
}

fn try_reserve_shard_queue_bytes(counter: &AtomicUsize, packet_bytes: usize, cap: usize) -> bool {
    loop {
        let current = counter.load(Ordering::Relaxed);
        let next = current.saturating_add(packet_bytes);
        if next > cap {
            return false;
        }
        if counter
            .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
    }
}

fn release_shard_queue_bytes(counter: &AtomicUsize, packet_bytes: usize) {
    loop {
        let current = counter.load(Ordering::Relaxed);
        let next = current.saturating_sub(packet_bytes);
        if counter
            .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
    }
}

fn maybe_pin_worker(worker_idx: usize, pin_workers: bool) {
    if !pin_workers {
        return;
    }

    let Some(core_ids) = core_affinity::get_core_ids() else {
        warn!("Worker pinning requested but core list is unavailable");
        return;
    };

    if core_ids.is_empty() {
        warn!("Worker pinning requested but no cores were reported");
        return;
    }

    let core_id = core_ids[worker_idx % core_ids.len()];
    if !core_affinity::set_for_current(core_id) {
        warn!("Failed to pin worker {} to core {}", worker_idx, core_id.id);
    }
}

fn join_worker_handle(handle: thread::JoinHandle<Result<(), String>>, worker_failed: &mut bool) {
    match handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            *worker_failed = true;
            error!("Worker exited with error: {}", err);
        }
        Err(payload) => {
            *worker_failed = true;
            error!(
                "Worker thread panicked: {}",
                runtime_guard::panic_payload_message(payload.as_ref())
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{release_shard_queue_bytes, shard_index_for_peer, try_reserve_shard_queue_bytes};
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn shard_index_is_stable_for_same_peer() {
        let peer: SocketAddr = "127.0.0.1:12345".parse().expect("peer addr");
        let a = shard_index_for_peer(&peer, 8);
        let b = shard_index_for_peer(&peer, 8);
        assert_eq!(a, b);
    }

    #[test]
    fn shard_index_is_within_bounds() {
        let peer: SocketAddr = "10.1.2.3:443".parse().expect("peer addr");
        let idx = shard_index_for_peer(&peer, 16);
        assert!(idx < 16);
    }

    #[test]
    fn shard_queue_byte_reservation_obeys_cap() {
        let counter = AtomicUsize::new(0);
        assert!(try_reserve_shard_queue_bytes(&counter, 10, 16));
        assert!(!try_reserve_shard_queue_bytes(&counter, 7, 16));
        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 10);
    }

    #[test]
    fn shard_queue_byte_release_is_saturating() {
        let counter = AtomicUsize::new(8);
        release_shard_queue_bytes(&counter, 3);
        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 5);
        release_shard_queue_bytes(&counter, 10);
        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}
