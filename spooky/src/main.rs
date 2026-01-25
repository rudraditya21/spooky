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

use clap::Parser;
use log::{error, info};

use spooky_config::validator::validate as validate_config;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    // Sets a custom config file
    #[arg(short, long)]
    config: Option<String>,
}

#[tokio::main]
async fn main() {
    // Parse CLI arguments
    let cli = Cli::parse();

    let config_path = cli
        .config
        .unwrap_or_else(|| "./config/config.yaml".to_string());

    // Read configuration file
    let config_yaml = match spooky_config::loader::read_config(&config_path) {
        Ok(cfg) => cfg,
        Err(err_msg) => {
            eprintln!("Error loading config: {}", err_msg);
            std::process::exit(1);
        }
    };

    // Initialize the Logger
    spooky_utils::logger::init_logger(&config_yaml.log.level);

    // Validate Configurations
    if validate_config(&config_yaml) == false {
        error!("Configuration validation failed. Exiting...");
        std::process::exit(1);
    }

    info!("Spooky is starting");
    let mut spooky = spooky_edge::QUICListener::new(config_yaml);

    loop {
        spooky.poll();
    }
}
