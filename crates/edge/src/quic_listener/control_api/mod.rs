use std::ffi::OsString;

use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use spooky_config::{
    config::ControlApi as ControlApiConfig, loader::read_config, runtime::RuntimeConfig,
};
use tokio_rustls::TlsAcceptor;

use super::*;

mod auth;
mod http;
mod context;
mod render;
mod reload;
mod service;
mod state;
mod watchdog;

#[cfg(test)]
mod tests;
