//! Analysis modules for binary analysis

#[cfg(feature = "control-flow")]
pub mod control_flow;

#[cfg(feature = "entropy-analysis")]
pub mod entropy;

pub mod security;
