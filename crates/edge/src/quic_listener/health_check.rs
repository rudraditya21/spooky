use super::*;

impl QUICListener {
    pub(super) fn spawn_health_checks(
        upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
        transport_pool: Arc<UpstreamTransportPool>,
        backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
        _backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
        metrics: Arc<Metrics>,
        task_registry: Arc<RuntimeTaskRegistry>,
    ) {
        struct HealthCheckJob {
            upstream_pool: Arc<RwLock<UpstreamPool>>,
            index: usize,
            // Stable configured backend identity. DNS refresh changes connect targets
            // underneath this identity without changing health ownership.
            backend_identity: String,
            health_uri: String,
            timeout: Duration,
            base_interval_ms: u64,
            consecutive_failures: u32,
            next_due_at: Instant,
        }

        let mut grouped_jobs: HashMap<u64, Vec<HealthCheckJob>> = HashMap::new();
        #[allow(clippy::for_kv_map)]
        for (_upstream_name, upstream_pool) in upstream_pools.iter() {
            let pool = match upstream_pool.read() {
                Ok(pool) => pool,
                Err(_) => continue,
            };
            for index in pool.pool.all_indices() {
                let (address, health) =
                    match (pool.pool.address(index), pool.pool.health_check(index)) {
                        (Some(address), Some(health)) => (address.to_string(), health),
                        _ => continue,
                    };
                let path: &str = if health.path.is_empty() {
                    "/"
                } else {
                    &health.path
                };
                let endpoint = match backend_endpoints.get(&address) {
                    Some(endpoint) => endpoint,
                    None => {
                        error!(
                            "disabling health checks for backend '{}' due to missing canonical endpoint",
                            address
                        );
                        continue;
                    }
                };
                let base_interval_ms = health.interval.max(1);
                let initial_jitter_ms = if base_interval_ms > 1 {
                    crate::stable_hash64(address.as_bytes()) % base_interval_ms
                } else {
                    0
                };
                let next_due_at = Instant::now() + Duration::from_millis(initial_jitter_ms);
                let job = HealthCheckJob {
                    upstream_pool: Arc::clone(upstream_pool),
                    index,
                    backend_identity: address,
                    health_uri: endpoint.uri_for_path(path),
                    timeout: Duration::from_millis(health.timeout_ms.max(1)),
                    base_interval_ms,
                    consecutive_failures: 0,
                    next_due_at,
                };
                grouped_jobs.entry(base_interval_ms).or_default().push(job);
            }
        }

        if grouped_jobs.is_empty() {
            return;
        }

        let handle = match runtime_handle() {
            Some(handle) => handle,
            None => {
                error!("Health checks disabled: no Tokio runtime available");
                return;
            }
        };

        for (base_interval_ms, mut jobs) in grouped_jobs {
            let transport_pool = Arc::clone(&transport_pool);
            let _backend_resolution_store = Arc::clone(&_backend_resolution_store);
            let task_metrics = Arc::clone(&metrics);
            let handle = handle.clone();
            let supervise_metrics = Arc::clone(&task_metrics);
            let registration = spawn_supervised_async_task(
                &handle,
                "health-check-group",
                Some(supervise_metrics),
                async move {
                    let scheduler_tick_ms = (base_interval_ms / 4).clamp(20, base_interval_ms);
                    let mut ticker =
                        tokio::time::interval(Duration::from_millis(scheduler_tick_ms.max(1)));
                    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                    loop {
                        ticker.tick().await;
                        let now = Instant::now();
                        for job in jobs.iter_mut() {
                            if now < job.next_due_at {
                                continue;
                            }

                            let request = match http::Request::builder()
                                .method("GET")
                                .uri(&job.health_uri)
                                .body(BoxBody::new(Full::new(Bytes::new())))
                            {
                                Ok(req) => req,
                                Err(_) => continue,
                            };

                            let result = tokio::time::timeout(
                                job.timeout,
                                transport_pool.send(&job.backend_identity, request),
                            )
                            .await;

                            let outcome = match result {
                                Ok(Ok(response)) => {
                                    classify_active_health_check_response(response.status())
                                }
                                Ok(Err(PoolError::Send(send_err))) => {
                                    let send_err_detail = Self::format_error_chain(&send_err);
                                    let (failure_reason, tls_reason) =
                                        Self::send_error_health_failure_reason(&send_err);
                                    if failure_reason == HealthFailureReason::Tls {
                                        task_metrics.record_upstream_tls_failure(
                                            &job.backend_identity,
                                            "health_check",
                                            tls_reason,
                                        );
                                        error!(
                                            "Health check upstream TLS failure for {} (tls_reason={}): {}",
                                            job.backend_identity, tls_reason, send_err_detail
                                        );
                                    }
                                    task_metrics.inc_health_failure(failure_reason);
                                    HealthClassification::Failure
                                }
                                Ok(Err(_)) => {
                                    task_metrics.inc_health_failure(HealthFailureReason::Transport);
                                    HealthClassification::Failure
                                }
                                Err(_) => {
                                    task_metrics.inc_health_failure(HealthFailureReason::Timeout);
                                    HealthClassification::Failure
                                }
                            };

                            let transition = match job.upstream_pool.write() {
                                Ok(mut pool) => match outcome {
                                    HealthClassification::Success => {
                                        task_metrics.inc_health_check_success();
                                        job.consecutive_failures = 0;
                                        pool.pool.mark_success(job.index)
                                    }
                                    HealthClassification::Failure => {
                                        task_metrics.inc_health_check_failure();
                                        job.consecutive_failures =
                                            job.consecutive_failures.saturating_add(1);
                                        pool.pool.mark_failure(job.index)
                                    }
                                    HealthClassification::Neutral => {
                                        job.consecutive_failures = 0;
                                        None
                                    }
                                },
                                Err(_) => None,
                            };

                            let backoff_multiplier = 1u64 << job.consecutive_failures.min(2);
                            let delay_ms = job.base_interval_ms.saturating_mul(backoff_multiplier);
                            job.next_due_at = Instant::now() + Duration::from_millis(delay_ms);

                            if let Some(transition) = transition {
                                Self::log_health_transition(&job.backend_identity, transition);
                            }
                        }
                    }
                },
            );
            task_registry.register(registration);
        }
    }
}

pub(super) fn classify_active_health_check_response(status: StatusCode) -> HealthClassification {
    outcome_from_status(status)
}
