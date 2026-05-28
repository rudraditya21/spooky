use super::*;

impl Metrics {
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(8 * 1024);
        out.push_str("# HELP spooky_requests_total Total requests seen by spooky.\n");
        out.push_str("# TYPE spooky_requests_total counter\n");
        out.push_str(&format!(
            "spooky_requests_total {}\n",
            self.requests_total.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP spooky_requests_success Total successful upstream responses.\n");
        out.push_str("# TYPE spooky_requests_success counter\n");
        out.push_str(&format!(
            "spooky_requests_success {}\n",
            self.requests_success.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP spooky_requests_failure Total failed requests.\n");
        out.push_str("# TYPE spooky_requests_failure counter\n");
        out.push_str(&format!(
            "spooky_requests_failure {}\n",
            self.requests_failure.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_request_validation_rejects Total requests rejected by protocol validation.\n",
        );
        out.push_str("# TYPE spooky_request_validation_rejects counter\n");
        out.push_str(&format!(
            "spooky_request_validation_rejects {}\n",
            self.request_validation_rejects.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_policy_denied Total requests denied by runtime method/path policies.\n",
        );
        out.push_str("# TYPE spooky_policy_denied counter\n");
        out.push_str(&format!(
            "spooky_policy_denied {}\n",
            self.policy_denied.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP spooky_early_data_accepted Total requests accepted in early data.\n");
        out.push_str("# TYPE spooky_early_data_accepted counter\n");
        out.push_str(&format!(
            "spooky_early_data_accepted {}\n",
            self.early_data_accepted.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP spooky_early_data_rejected Total requests rejected in early data.\n");
        out.push_str("# TYPE spooky_early_data_rejected counter\n");
        out.push_str(&format!(
            "spooky_early_data_rejected {}\n",
            self.early_data_rejected.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP spooky_health_checks_total Total active health checks executed.\n");
        out.push_str("# TYPE spooky_health_checks_total counter\n");
        out.push_str(&format!(
            "spooky_health_checks_total {}\n",
            self.health_checks_total.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_health_checks_success Total successful active health checks.\n",
        );
        out.push_str("# TYPE spooky_health_checks_success counter\n");
        out.push_str(&format!(
            "spooky_health_checks_success {}\n",
            self.health_checks_success.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP spooky_health_checks_failure Total failed active health checks.\n");
        out.push_str("# TYPE spooky_health_checks_failure counter\n");
        out.push_str(&format!(
            "spooky_health_checks_failure {}\n",
            self.health_checks_failure.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP spooky_backend_timeouts Total backend timeout events.\n");
        out.push_str("# TYPE spooky_backend_timeouts counter\n");
        out.push_str(&format!(
            "spooky_backend_timeouts {}\n",
            self.backend_timeouts.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP spooky_backend_errors Total backend error events.\n");
        out.push_str("# TYPE spooky_backend_errors counter\n");
        out.push_str(&format!(
            "spooky_backend_errors {}\n",
            self.backend_errors.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_overload_shed Total requests dropped due to overload controls.\n",
        );
        out.push_str("# TYPE spooky_overload_shed counter\n");
        out.push_str(&format!(
            "spooky_overload_shed {}\n",
            self.overload_shed.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_overload_shed_by_reason_total Total overload shed decisions grouped by reason.\n",
        );
        out.push_str("# TYPE spooky_overload_shed_by_reason_total counter\n");
        out.push_str(&format!(
            "spooky_overload_shed_by_reason_total{{reason=\"brownout\"}} {}\n",
            self.overload_shed_brownout.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "spooky_overload_shed_by_reason_total{{reason=\"adaptive_admission\"}} {}\n",
            self.overload_shed_adaptive.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "spooky_overload_shed_by_reason_total{{reason=\"route_cap\"}} {}\n",
            self.overload_shed_route_cap.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "spooky_overload_shed_by_reason_total{{reason=\"route_global_cap\"}} {}\n",
            self.overload_shed_route_global_cap.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "spooky_overload_shed_by_reason_total{{reason=\"global_inflight\"}} {}\n",
            self.overload_shed_global_inflight.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "spooky_overload_shed_by_reason_total{{reason=\"upstream_inflight\"}} {}\n",
            self.overload_shed_upstream_inflight.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "spooky_overload_shed_by_reason_total{{reason=\"backend_inflight\"}} {}\n",
            self.overload_shed_backend_inflight.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "spooky_overload_shed_by_reason_total{{reason=\"circuit_open\"}} {}\n",
            self.overload_shed_circuit_open.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "spooky_overload_shed_by_reason_total{{reason=\"request_buffer_cap\"}} {}\n",
            self.overload_shed_request_buffer.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "spooky_overload_shed_by_reason_total{{reason=\"response_prebuffer_cap\"}} {}\n",
            self.overload_shed_response_prebuffer
                .load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "spooky_overload_shed_by_reason_total{{reason=\"connection_cap\"}} {}\n",
            self.overload_shed_connection_cap.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP spooky_active_connections Current active QUIC connections.\n");
        out.push_str("# TYPE spooky_active_connections gauge\n");
        out.push_str(&format!(
            "spooky_active_connections {}\n",
            self.active_connections.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_connection_cap_rejects Total new-connection attempts rejected by max_active_connections cap.\n",
        );
        out.push_str("# TYPE spooky_connection_cap_rejects counter\n");
        out.push_str(&format!(
            "spooky_connection_cap_rejects {}\n",
            self.connection_cap_rejects.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP spooky_hedge_triggered_total Total hedge attempts started.\n");
        out.push_str("# TYPE spooky_hedge_triggered_total counter\n");
        out.push_str(&format!(
            "spooky_hedge_triggered_total {}\n",
            self.hedge_triggered.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_hedge_won_total Total requests where hedge response arrived first.\n",
        );
        out.push_str("# TYPE spooky_hedge_won_total counter\n");
        out.push_str(&format!(
            "spooky_hedge_won_total {}\n",
            self.hedge_won.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_hedge_wasted_total Total hedge attempts that did not win the race.\n",
        );
        out.push_str("# TYPE spooky_hedge_wasted_total counter\n");
        out.push_str(&format!(
            "spooky_hedge_wasted_total {}\n",
            self.hedge_wasted.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_hedge_primary_won_after_trigger_total Total hedged requests where primary still won.\n",
        );
        out.push_str("# TYPE spooky_hedge_primary_won_after_trigger_total counter\n");
        out.push_str(&format!(
            "spooky_hedge_primary_won_after_trigger_total {}\n",
            self.hedge_primary_won_after_trigger.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_hedge_primary_late_ms_total Aggregate milliseconds primary was late after hedge trigger.\n",
        );
        out.push_str("# TYPE spooky_hedge_primary_late_ms_total counter\n");
        out.push_str(&format!(
            "spooky_hedge_primary_late_ms_total {}\n",
            self.hedge_primary_late_ms_total.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_hedge_primary_late_samples_total Number of late-primary observations used in hedge tuning.\n",
        );
        out.push_str("# TYPE spooky_hedge_primary_late_samples_total counter\n");
        out.push_str(&format!(
            "spooky_hedge_primary_late_samples_total {}\n",
            self.hedge_primary_late_samples.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_ingress_packets_total Total UDP packets processed by ingress.\n",
        );
        out.push_str("# TYPE spooky_ingress_packets_total counter\n");
        out.push_str(&format!(
            "spooky_ingress_packets_total {}\n",
            self.ingress_packets_total.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_ingress_queue_drops Total ingress packets dropped due to full shard queues.\n",
        );
        out.push_str("# TYPE spooky_ingress_queue_drops counter\n");
        out.push_str(&format!(
            "spooky_ingress_queue_drops {}\n",
            self.ingress_queue_drops.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_ingress_queue_drop_bytes Total UDP datagram bytes dropped due to full shard queues.\n",
        );
        out.push_str("# TYPE spooky_ingress_queue_drop_bytes counter\n");
        out.push_str(&format!(
            "spooky_ingress_queue_drop_bytes {}\n",
            self.ingress_queue_drop_bytes.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_ingress_queue_bytes Current bytes buffered in ingress shard queues.\n",
        );
        out.push_str("# TYPE spooky_ingress_queue_bytes gauge\n");
        out.push_str(&format!(
            "spooky_ingress_queue_bytes {}\n",
            self.ingress_queue_bytes.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_ingress_bad_header_total Ingress packets dropped due to unparseable QUIC header.\n",
        );
        out.push_str("# TYPE spooky_ingress_bad_header_total counter\n");
        out.push_str(&format!(
            "spooky_ingress_bad_header_total {}\n",
            self.ingress_bad_header_total.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_ingress_rate_limited_total Initial packets dropped by the new-connection rate limiter.\n",
        );
        out.push_str("# TYPE spooky_ingress_rate_limited_total counter\n");
        out.push_str(&format!(
            "spooky_ingress_rate_limited_total {}\n",
            self.ingress_rate_limited_total.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_ingress_unroutable_total Non-Initial packets received for unknown connections.\n",
        );
        out.push_str("# TYPE spooky_ingress_unroutable_total counter\n");
        out.push_str(&format!(
            "spooky_ingress_unroutable_total {}\n",
            self.ingress_unroutable_total.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_ingress_draining_drops_total Packets dropped because the listener is draining.\n",
        );
        out.push_str("# TYPE spooky_ingress_draining_drops_total counter\n");
        out.push_str(&format!(
            "spooky_ingress_draining_drops_total {}\n",
            self.ingress_draining_drops_total.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_ingress_connection_create_failed_total Packets dropped because quiche::accept() failed to create a new connection.\n",
        );
        out.push_str("# TYPE spooky_ingress_connection_create_failed_total counter\n");
        out.push_str(&format!(
            "spooky_ingress_connection_create_failed_total {}\n",
            self.ingress_connection_create_failed_total
                .load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_ingress_version_neg_failed_total Packets dropped because version negotiation response could not be constructed.\n",
        );
        out.push_str("# TYPE spooky_ingress_version_neg_failed_total counter\n");
        out.push_str(&format!(
            "spooky_ingress_version_neg_failed_total {}\n",
            self.ingress_version_neg_failed_total
                .load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_request_buffered_bytes Current bytes buffered in request backpressure queues.\n",
        );
        out.push_str("# TYPE spooky_request_buffered_bytes gauge\n");
        out.push_str(&format!(
            "spooky_request_buffered_bytes {}\n",
            self.request_buffered_bytes.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_request_buffered_high_watermark_bytes Peak request-buffered bytes since process start.\n",
        );
        out.push_str("# TYPE spooky_request_buffered_high_watermark_bytes gauge\n");
        out.push_str(&format!(
            "spooky_request_buffered_high_watermark_bytes {}\n",
            self.request_buffered_high_watermark_bytes
                .load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_request_buffer_limit_rejects Total requests rejected due to request buffer byte caps.\n",
        );
        out.push_str("# TYPE spooky_request_buffer_limit_rejects counter\n");
        out.push_str(&format!(
            "spooky_request_buffer_limit_rejects {}\n",
            self.request_buffer_limit_rejects.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_response_prebuffer_limit_rejects Total unknown-length upstream responses rejected due to prebuffer cap.\n",
        );
        out.push_str("# TYPE spooky_response_prebuffer_limit_rejects counter\n");
        out.push_str(&format!(
            "spooky_response_prebuffer_limit_rejects {}\n",
            self.response_prebuffer_limit_rejects
                .load(Ordering::Relaxed)
        ));

        out.push_str("# HELP spooky_scid_rotations Total SCID rotations.\n");
        out.push_str("# TYPE spooky_scid_rotations counter\n");
        out.push_str(&format!(
            "spooky_scid_rotations {}\n",
            self.scid_rotations.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_control_api_connection_limit_drops Total control API connections dropped due to max-connection limiter.\n",
        );
        out.push_str("# TYPE spooky_control_api_connection_limit_drops counter\n");
        out.push_str(&format!(
            "spooky_control_api_connection_limit_drops {}\n",
            self.control_api_connection_limit_drops
                .load(Ordering::Relaxed)
        ));

        out.push_str("# HELP spooky_watchdog_restart_requests Total watchdog restart requests.\n");
        out.push_str("# TYPE spooky_watchdog_restart_requests counter\n");
        out.push_str(&format!(
            "spooky_watchdog_restart_requests {}\n",
            self.watchdog_restart_requests.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_watchdog_restart_hooks Total executed watchdog restart hooks.\n",
        );
        out.push_str("# TYPE spooky_watchdog_restart_hooks counter\n");
        out.push_str(&format!(
            "spooky_watchdog_restart_hooks {}\n",
            self.watchdog_restart_hooks.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP spooky_runtime_panics Total runtime task panics observed.\n");
        out.push_str("# TYPE spooky_runtime_panics counter\n");
        out.push_str(&format!(
            "spooky_runtime_panics {}\n",
            self.runtime_panics.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_watchdog_degraded_windows Total degraded watchdog evaluation windows.\n",
        );
        out.push_str("# TYPE spooky_watchdog_degraded_windows counter\n");
        out.push_str(&format!(
            "spooky_watchdog_degraded_windows {}\n",
            self.watchdog_degraded_windows.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP spooky_retries_total Total retry attempts across all routes.\n");
        out.push_str("# TYPE spooky_retries_total counter\n");
        out.push_str(&format!(
            "spooky_retries_total {}\n",
            self.retries_total.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_retry_denied_total Total retry attempts blocked, by denial reason.\n",
        );
        out.push_str("# TYPE spooky_retry_denied_total counter\n");
        out.push_str(&format!(
            "spooky_retry_denied_total{{reason=\"budget\"}} {}\n",
            self.retry_denied_budget.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "spooky_retry_denied_total{{reason=\"no_bodyless\"}} {}\n",
            self.retry_denied_no_bodyless.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "spooky_retry_denied_total{{reason=\"no_alternate\"}} {}\n",
            self.retry_denied_no_alternate.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_retry_attempts_total Total retries triggered, by error reason.\n",
        );
        out.push_str("# TYPE spooky_retry_attempts_total counter\n");
        out.push_str(&format!(
            "spooky_retry_attempts_total{{reason=\"timeout\"}} {}\n",
            self.retry_reason_timeout.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "spooky_retry_attempts_total{{reason=\"transport\"}} {}\n",
            self.retry_reason_transport.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "spooky_retry_attempts_total{{reason=\"pool\"}} {}\n",
            self.retry_reason_pool.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP spooky_circuit_breaker_rejected_total Requests rejected by an open circuit breaker.\n");
        out.push_str("# TYPE spooky_circuit_breaker_rejected_total counter\n");
        out.push_str(&format!(
            "spooky_circuit_breaker_rejected_total {}\n",
            self.circuit_breaker_rejected_total.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP spooky_brownout_active Whether brownout mode is currently active (1=active, 0=inactive).\n");
        out.push_str("# TYPE spooky_brownout_active gauge\n");
        out.push_str(&format!(
            "spooky_brownout_active {}\n",
            self.brownout_active.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP spooky_health_failures_total Backend health failures, by failure reason.\n",
        );
        out.push_str("# TYPE spooky_health_failures_total counter\n");
        out.push_str(&format!(
            "spooky_health_failures_total{{reason=\"5xx\"}} {}\n",
            self.health_failure_5xx.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "spooky_health_failures_total{{reason=\"timeout\"}} {}\n",
            self.health_failure_timeout.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "spooky_health_failures_total{{reason=\"transport\"}} {}\n",
            self.health_failure_transport.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "spooky_health_failures_total{{reason=\"tls\"}} {}\n",
            self.health_failure_tls.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP spooky_route_latency_sample_every Route latency histogram sampling interval (1 = every request).\n",
        );
        out.push_str("# TYPE spooky_route_latency_sample_every gauge\n");
        out.push_str(&format!(
            "spooky_route_latency_sample_every {}\n",
            self.route_latency_sample_every
        ));

        let mut snapshot: Vec<(String, RouteStats)> = self
            .route_labels
            .iter()
            .enumerate()
            .filter_map(|(idx, route)| {
                self.route_stats
                    .get(idx)
                    .map(|stats| (route.clone(), stats.snapshot()))
            })
            .collect();
        snapshot.sort_by(|(left, _), (right, _)| left.cmp(right));

        for (route, stats) in snapshot {
            let route = escape_prometheus_label(&route);
            out.push_str(&format!(
                "spooky_route_requests_total{{route=\"{}\"}} {}\n",
                route, stats.requests_total
            ));
            out.push_str(&format!(
                "spooky_route_success_total{{route=\"{}\"}} {}\n",
                route, stats.success
            ));
            out.push_str(&format!(
                "spooky_route_failure_total{{route=\"{}\"}} {}\n",
                route, stats.failure
            ));
            out.push_str(&format!(
                "spooky_route_timeout_total{{route=\"{}\"}} {}\n",
                route, stats.timeout
            ));
            out.push_str(&format!(
                "spooky_route_backend_error_total{{route=\"{}\"}} {}\n",
                route, stats.backend_error
            ));
            out.push_str(&format!(
                "spooky_route_overload_shed_total{{route=\"{}\"}} {}\n",
                route, stats.overload_shed
            ));
            out.push_str(&format!(
                "spooky_route_latency_ms_p50{{route=\"{}\"}} {:.2}\n",
                route,
                percentile_ms(&stats, 0.50)
            ));
            out.push_str(&format!(
                "spooky_route_latency_ms_p95{{route=\"{}\"}} {:.2}\n",
                route,
                percentile_ms(&stats, 0.95)
            ));
            out.push_str(&format!(
                "spooky_route_latency_ms_p99{{route=\"{}\"}} {:.2}\n",
                route,
                percentile_ms(&stats, 0.99)
            ));
        }

        let mut worker_snapshot: Vec<(String, WorkerStats)> = self
            .worker_labels
            .iter()
            .enumerate()
            .filter_map(|(idx, worker)| {
                self.worker_stats
                    .get(idx)
                    .map(|stats| (worker.clone(), stats.snapshot()))
            })
            .collect();
        worker_snapshot.sort_by(|(left, _), (right, _)| left.cmp(right));

        out.push_str(
            "# HELP spooky_worker_requests_total Total requests handled by each worker thread.\n",
        );
        out.push_str("# TYPE spooky_worker_requests_total counter\n");
        out.push_str(
            "# HELP spooky_worker_requests_success Total successful requests by worker thread.\n",
        );
        out.push_str("# TYPE spooky_worker_requests_success counter\n");
        out.push_str(
            "# HELP spooky_worker_requests_failure Total failed requests by worker thread.\n",
        );
        out.push_str("# TYPE spooky_worker_requests_failure counter\n");
        out.push_str(
            "# HELP spooky_worker_ingress_packets_total Total ingress packets by worker thread.\n",
        );
        out.push_str("# TYPE spooky_worker_ingress_packets_total counter\n");
        out.push_str(
            "# HELP spooky_worker_ingress_queue_drops Total ingress queue drops by worker thread.\n",
        );
        out.push_str("# TYPE spooky_worker_ingress_queue_drops counter\n");
        out.push_str(
            "# HELP spooky_worker_ingress_queue_drop_bytes Total ingress queue drop bytes by worker thread.\n",
        );
        out.push_str("# TYPE spooky_worker_ingress_queue_drop_bytes counter\n");

        for (worker, stats) in worker_snapshot {
            let worker = escape_prometheus_label(&worker);
            out.push_str(&format!(
                "spooky_worker_requests_total{{worker=\"{}\"}} {}\n",
                worker, stats.requests_total
            ));
            out.push_str(&format!(
                "spooky_worker_requests_success{{worker=\"{}\"}} {}\n",
                worker, stats.requests_success
            ));
            out.push_str(&format!(
                "spooky_worker_requests_failure{{worker=\"{}\"}} {}\n",
                worker, stats.requests_failure
            ));
            out.push_str(&format!(
                "spooky_worker_ingress_packets_total{{worker=\"{}\"}} {}\n",
                worker, stats.ingress_packets_total
            ));
            out.push_str(&format!(
                "spooky_worker_ingress_queue_drops{{worker=\"{}\"}} {}\n",
                worker, stats.ingress_queue_drops
            ));
            out.push_str(&format!(
                "spooky_worker_ingress_queue_drop_bytes{{worker=\"{}\"}} {}\n",
                worker, stats.ingress_queue_drop_bytes
            ));
        }

        out
    }
}

fn percentile_ms(stats: &RouteStats, quantile: f64) -> f64 {
    if stats.requests_total == 0 {
        return 0.0;
    }

    let target = ((stats.requests_total as f64) * quantile).ceil() as u64;
    let mut running = 0u64;

    for (idx, count) in stats.latency_buckets.iter().enumerate() {
        running = running.saturating_add(*count);
        if running >= target {
            return if idx < LATENCY_BUCKETS_MS.len() {
                LATENCY_BUCKETS_MS[idx] as f64
            } else {
                *LATENCY_BUCKETS_MS.last().unwrap_or(&60_000) as f64
            };
        }
    }

    *LATENCY_BUCKETS_MS.last().unwrap_or(&60_000) as f64
}

fn escape_prometheus_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}
