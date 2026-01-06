//! Spooky HTTP/3 Load Balancer - Main Entry Point
//! 
//! TODO: Implement graceful shutdown signal handling
//! TODO: Implement proper error handling for server initialization
//! TODO: Add health check endpoint for load balancer itself
//! TODO: Add metrics collection and monitoring endpoints
//! TODO: Implement configuration hot-reload capability
//! TODO: Add structured logging with request tracing
//! TODO: Add startup banner and version information
//! TODO: Implement proper process lifecycle management

//! TODO: Setup the client and use that for proxing request rather than client for every request

use clap::{Parser};

// proxy http3 server QUIC + HTTP/3
use log::{info, debug, error, LevelFilter};
use env_logger;

pub mod config;
pub mod utils;
pub mod lb;

pub mod edge;
pub mod bridge;
pub mod transport;

use crate::config::validator::{validate as validate_config};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {    
    // Sets a custom config file
    #[arg(short, long)]
    config: Option<String>,
}

fn init_logger(log_level: &str) {
    let level = match log_level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        "off" => LevelFilter::Off,
        _ => {
            eprintln!("Invalid log level '{}', defaulting to 'info'", log_level);
            LevelFilter::Info
        }
    };

    env_logger::Builder::from_default_env()
        .filter_level(level)
        .format_timestamp_secs()
        .init();
}

#[tokio::main]
async fn main() {
    // TODO: Add startup banner with version and build info
    

    // TODO: Implement signal handling for graceful shutdown (SIGTERM, SIGINT)
    // TODO: Add panic hook for proper error reporting
    // TODO: Implement proper error handling instead of expect() calls
    // TODO: Add startup health checks before accepting connections
    // TODO: Add metrics server startup
    // TODO: Implement proper process lifecycle management

    // Parse CLI arguments
    let cli = Cli::parse();

    let config_path = cli.config.unwrap_or_else(|| "./config/config.yaml".to_string());

    // Read configuration file
    let config_yaml = match config::loader::read_config(&config_path) {
        Ok(cfg) => cfg,
        Err(err_msg) => {
            eprintln!("Error loading config: {}", err_msg);
            std::process::exit(1);
        }
    };

    // Initialize the Logger
    init_logger(&config_yaml.log.level);
    
    // Validate Configurations
    if validate_config(&config_yaml) == false {
        error!("Configuration validation failed. Exiting...");
        std::process::exit(1);
    }

    let spooky = edge::QUICListener::new(config_yaml);

    loop {
        spooky.poll();
    }
}
