use std::{
    sync::{Arc, atomic::AtomicUsize},
    time::Duration,
};

use bytes::Bytes;
use ::http::{Response, StatusCode};
use http_body_util::Full;
use hyper::{Request, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use log::{debug, error, info};
use spooky_config::config::MetricsEndpoint;
use spooky_errors::ProxyError;

use super::{
    QUICListener,
    runtime_endpoint::RuntimeConnectionSlotGuard,
    runtime_handle,
    runtime_state::{ControlPlaneBootstrap, MetricsServiceCtx},
    spawn_supervised_async_task,
};
use crate::Metrics;

mod service;
mod state;
mod http;
