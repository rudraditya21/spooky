use super::*;

impl RuntimeListener {
    pub(super) fn new(
        index: usize,
        source: RuntimeListenerSource,
        listen: Listen,
        label: &str,
    ) -> Result<Self, RuntimeConfigError> {
        let tls = RuntimeListenerTls::normalize(&listen, label)?;
        Ok(Self {
            index,
            source,
            listen,
            tls,
        })
    }

    pub fn bind_key(&self) -> (String, u16) {
        (
            self.listen.address.trim().to_ascii_lowercase(),
            self.listen.port,
        )
    }
}

impl RuntimeListenerTls {
    pub fn normalize(listen: &Listen, label: &str) -> Result<Self, RuntimeConfigError> {
        let mut sni_identities = HashMap::new();
        let legacy_identity = RuntimeTlsIdentity::from_legacy_pair(listen, label)?;

        if !listen.tls.client_auth.enabled && listen.tls.client_auth.require_client_cert {
            return Err(RuntimeConfigError::UnsupportedPolicyCombination(format!(
                "{label}.tls.client_auth.require_client_cert requires client_auth.enabled=true"
            )));
        }
        if listen.tls.client_auth.enabled {
            let Some(ca_file) = listen.tls.client_auth.ca_file.as_deref().map(str::trim) else {
                return Err(RuntimeConfigError::TlsMaterialInvalid(format!(
                    "{label}.tls.client_auth.ca_file is required when client_auth.enabled=true"
                )));
            };
            if ca_file.is_empty() {
                return Err(RuntimeConfigError::TlsMaterialInvalid(format!(
                    "{label}.tls.client_auth.ca_file must be non-empty when client_auth.enabled=true"
                )));
            }
        }

        for entry in &listen.tls.certificates {
            let identity = RuntimeTlsIdentity::from_certificate(entry, label)?;
            let server_name = super::upstreams::normalize_sni_server_name(&entry.server_name)
                .ok_or_else(|| {
                    RuntimeConfigError::TlsMaterialInvalid(format!(
                        "{label}.tls.certificates entries must include a valid DNS server_name"
                    ))
                })?;
            if let Some(existing) = sni_identities.insert(server_name.clone(), identity) {
                return Err(RuntimeConfigError::TlsMaterialInvalid(format!(
                    "{label}.tls.certificates contains duplicate server_name '{server_name}' for '{}' and '{}'",
                    existing.cert_path, entry.cert
                )));
            }
        }

        let default_identity = match legacy_identity {
            Some(identity) => identity,
            None => listen
                .tls
                .certificates
                .first()
                .map(|entry| RuntimeTlsIdentity::from_certificate(entry, label))
                .transpose()?
                .ok_or_else(|| {
                    RuntimeConfigError::TlsMaterialInvalid(format!(
                        "{label}.tls requires either cert/key or certificates entries"
                    ))
                })?,
        };

        Ok(Self {
            default_identity,
            sni_identities,
            client_auth: listen.tls.client_auth.clone(),
        })
    }
}

impl RuntimeTlsIdentity {
    pub(super) fn from_certificate(
        certificate: &TlsCertificate,
        label: &str,
    ) -> Result<Self, RuntimeConfigError> {
        let server_name = certificate.server_name.trim();
        if server_name.is_empty() {
            return Err(RuntimeConfigError::TlsMaterialInvalid(format!(
                "{label}.tls.certificates entries must include a non-empty server_name"
            )));
        }

        let cert_path = certificate.cert.trim();
        let key_path = certificate.key.trim();
        if cert_path.is_empty() || key_path.is_empty() {
            return Err(RuntimeConfigError::TlsMaterialInvalid(format!(
                "{label}.tls.certificates entries must include non-empty cert and key"
            )));
        }

        Ok(Self {
            cert_path: cert_path.to_string(),
            key_path: key_path.to_string(),
        })
    }

    pub(super) fn from_legacy_pair(
        listen: &Listen,
        label: &str,
    ) -> Result<Option<Self>, RuntimeConfigError> {
        let cert = listen.tls.cert.trim();
        let key = listen.tls.key.trim();
        if cert.is_empty() || key.is_empty() {
            if cert.is_empty() && key.is_empty() {
                return Ok(None);
            }
            return Err(RuntimeConfigError::TlsMaterialInvalid(format!(
                "{label}.tls.cert and {label}.tls.key must both be set when either is provided"
            )));
        }

        Ok(Some(Self {
            cert_path: cert.to_string(),
            key_path: key.to_string(),
        }))
    }
}

pub fn runtime_listeners(config: &Config) -> Result<Vec<RuntimeListener>, RuntimeConfigError> {
    let listeners = if config.listeners.is_empty() {
        vec![RuntimeListener::new(
            0,
            RuntimeListenerSource::LegacyListen,
            config.listen.clone(),
            "listen",
        )?]
    } else {
        config
            .listeners
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, listen)| {
                RuntimeListener::new(
                    index,
                    RuntimeListenerSource::ExplicitListeners,
                    listen,
                    &format!("listeners[{index}]"),
                )
            })
            .collect::<Result<Vec<_>, _>>()?
    };

    validate_listener_bindings(&listeners)?;
    Ok(listeners)
}

fn validate_listener_bindings(listeners: &[RuntimeListener]) -> Result<(), RuntimeConfigError> {
    let mut seen = HashMap::new();
    for listener in listeners {
        let bind_key = listener.bind_key();
        let current = format!(
            "{}:{} (listener #{})",
            listener.listen.address, listener.listen.port, listener.index
        );
        if let Some(existing) = seen.insert(bind_key, current.clone()) {
            return Err(RuntimeConfigError::ListenerBindConflict {
                current,
                existing,
                address: listener.listen.address.clone(),
                port: listener.listen.port,
            });
        }
    }

    Ok(())
}
