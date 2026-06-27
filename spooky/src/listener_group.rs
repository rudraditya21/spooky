use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::{thread, time::Duration};

use log::{error, info, warn};

use spooky_config::runtime::{ListenerRuntimeConfig, RuntimeConfig};
use spooky_edge::types::RuntimeBundleHandle;
use spooky_edge::{
    QUICListener, SharedRuntimeState, constants::MAX_DATAGRAM_SIZE_BYTES, stable_hash_socket_addr,
};

use crate::runtime_guard;

struct IngressPacket {
    peer: SocketAddr,
    local_addr: SocketAddr,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ListenerGroupSignature {
    pub(crate) label: String,
    pub(crate) worker_count: usize,
    shard_count: usize,
    shard_queue_capacity: usize,
    shard_queue_max_bytes: usize,
    pin_workers: bool,
    reuseport: bool,
    udp_recv_buffer_bytes: usize,
    udp_send_buffer_bytes: usize,
}

pub(crate) struct ListenerGroupRuntime {
    pub(crate) signature: ListenerGroupSignature,
    pub(crate) shutdown: Arc<AtomicBool>,
    worker_handles: Vec<thread::JoinHandle<Result<(), String>>>,
}

impl ListenerGroupRuntime {
    pub(crate) fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    pub(crate) fn collect_finished(&mut self, worker_failed: &mut bool) {
        let mut idx = 0usize;
        while idx < self.worker_handles.len() {
            if !self.worker_handles[idx].is_finished() {
                idx += 1;
                continue;
            }

            let handle = self.worker_handles.swap_remove(idx);
            join_worker_handle(handle, worker_failed);
        }
    }

    pub(crate) fn retired(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed) && self.worker_handles.is_empty()
    }

    pub(crate) fn join_all(mut self, worker_failed: &mut bool) {
        for handle in self.worker_handles.drain(..) {
            join_worker_handle(handle, worker_failed);
        }
    }
}

pub(crate) fn listener_label(config: &ListenerRuntimeConfig) -> String {
    format!(
        "{}:{}",
        config.listen.listen.address, config.listen.listen.port
    )
}

pub(crate) fn listener_group_signature(config: &ListenerRuntimeConfig) -> ListenerGroupSignature {
    ListenerGroupSignature {
        label: listener_label(config),
        worker_count: config.performance.worker_threads.max(1),
        shard_count: config.performance.packet_shards_per_worker.max(1),
        shard_queue_capacity: config.performance.packet_shard_queue_capacity.max(1),
        shard_queue_max_bytes: config.performance.packet_shard_queue_max_bytes.max(1),
        pin_workers: config.performance.pin_workers,
        reuseport: config.performance.reuseport,
        udp_recv_buffer_bytes: config.performance.udp_recv_buffer_bytes,
        udp_send_buffer_bytes: config.performance.udp_send_buffer_bytes,
    }
}

pub(crate) fn spawn_managed_listener_group(
    listener_config: ListenerRuntimeConfig,
    worker_shared: Arc<SharedRuntimeState>,
    runtime_bundle: Arc<RuntimeBundleHandle>,
    worker_index_base: usize,
) -> Result<ListenerGroupRuntime, String> {
    let signature = listener_group_signature(&listener_config);
    let shutdown = Arc::new(AtomicBool::new(false));

    QUICListener::spawn_bootstrap_tls_listener(
        &listener_config,
        worker_shared.as_ref(),
        Some(Arc::clone(&runtime_bundle)),
        Some(Arc::clone(&shutdown)),
    )
    .map_err(|err| {
        format!(
            "Failed to initialize bootstrap TLS listener {} ({}:{}): {}",
            listener_config.listen.index,
            listener_config.listen.listen.address,
            listener_config.listen.listen.port,
            err
        )
    })?;

    let worker_handles = spawn_listener_worker_group(
        listener_config,
        signature.worker_count,
        signature.shard_count,
        signature.shard_queue_capacity,
        signature.shard_queue_max_bytes,
        signature.pin_workers,
        worker_shared,
        runtime_bundle,
        Arc::clone(&shutdown),
        worker_index_base,
    )?;

    Ok(ListenerGroupRuntime {
        signature,
        shutdown,
        worker_handles,
    })
}

pub(crate) fn reconcile_listener_groups(
    runtime_bundle: &Arc<RuntimeBundleHandle>,
    groups: &mut Vec<ListenerGroupRuntime>,
    next_worker_index_base: &mut usize,
) {
    let runtime = runtime_bundle.current();
    let desired_configs = runtime.runtime_config.listener_runtime_configs();
    let desired_signatures = desired_configs
        .iter()
        .map(|config| (listener_label(config), listener_group_signature(config)))
        .collect::<HashMap<_, _>>();

    for group in groups.iter_mut() {
        match desired_signatures.get(&group.signature.label) {
            Some(signature) if signature == &group.signature => {}
            Some(signature) => {
                if !group.shutdown.load(Ordering::Relaxed) {
                    info!(
                        "Retiring listener group {} for topology reload",
                        signature.label
                    );
                    group.request_shutdown();
                }
            }
            None => {
                if !group.shutdown.load(Ordering::Relaxed) {
                    info!(
                        "Retiring listener group {} because it is no longer configured",
                        group.signature.label
                    );
                    group.request_shutdown();
                }
            }
        }
    }

    for listener_config in desired_configs {
        let signature = listener_group_signature(&listener_config);
        let active_match = groups.iter().any(|group| {
            group.signature.label == signature.label && !group.shutdown.load(Ordering::Relaxed)
        });
        let pending_retire = groups
            .iter()
            .any(|group| group.signature.label == signature.label);
        if active_match || pending_retire {
            continue;
        }

        match spawn_managed_listener_group(
            listener_config,
            Arc::clone(&runtime.shared_state),
            Arc::clone(runtime_bundle),
            *next_worker_index_base,
        ) {
            Ok(group) => {
                info!("Spawned listener group {}", group.signature.label);
                *next_worker_index_base =
                    next_worker_index_base.saturating_add(group.signature.worker_count);
                groups.push(group);
            }
            Err(err) => {
                error!("{}", err);
            }
        }
    }
}

pub(crate) fn collect_finished_listener_groups(
    groups: &mut Vec<ListenerGroupRuntime>,
    worker_failed: &mut bool,
) {
    let mut idx = 0usize;
    while idx < groups.len() {
        groups[idx].collect_finished(worker_failed);
        if groups[idx].retired() {
            info!("Retired listener group {}", groups[idx].signature.label);
            groups.swap_remove(idx);
            continue;
        }
        idx += 1;
    }
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

pub(crate) fn shard_index_for_peer(peer: &SocketAddr, shard_count: usize) -> usize {
    (stable_hash_socket_addr(peer) as usize) % shard_count.max(1)
}

pub(crate) fn try_reserve_shard_queue_bytes(
    counter: &AtomicUsize,
    packet_bytes: usize,
    cap: usize,
) -> bool {
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

pub(crate) fn release_shard_queue_bytes(counter: &AtomicUsize, packet_bytes: usize) {
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

pub(crate) fn log_listener_startup(
    runtime_config: &RuntimeConfig,
    listener_groups: &[ListenerGroupRuntime],
) {
    let shard_count = runtime_config.performance.packet_shards_per_worker.max(1);
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
        listener_groups
            .iter()
            .map(group_signature_worker_count)
            .sum::<usize>(),
        shard_count,
        runtime_config.performance.reuseport,
        runtime_config.performance.pin_workers
    );
}

fn group_signature_worker_count(group: &ListenerGroupRuntime) -> usize {
    group.signature.worker_count
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
