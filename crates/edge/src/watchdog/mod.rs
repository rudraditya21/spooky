//! Watchdog coordination for the edge runtime.
//!
//! The public surface is intentionally small: external callers interact with
//! the coordinator, while service execution, timing helpers, and config
//! translation stay internal to the crate.

pub(crate) mod config;
pub mod coordinator;
pub(crate) mod service;
pub(crate) mod state;
pub(crate) mod time;
