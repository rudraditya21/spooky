//! Load-balancing primitives for runtime-selected backend picking.
//!
//! Canonical consumers should depend on [`upstream_pool`], [`load_balancing`],
//! [`alternate_backend`], and [`health`]. The remaining modules are kept
//! visible only as compatibility/testing substrate and are not intended as
//! orchestration entrypoints.

#[doc(hidden)]
pub mod algorithms;
pub mod alternate_backend;
#[doc(hidden)]
pub mod backend;
#[doc(hidden)]
pub mod backend_pool;
pub(crate) mod hash;
pub mod health;
pub mod load_balancing;
pub mod upstream_pool;
