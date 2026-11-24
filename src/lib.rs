//! bosun — library root. The binary (`main.rs`) is a thin shell
//! over this crate: it dispatches the subcommands (`mdm-serve`,
//! `ca-init`, `approve`) and otherwise runs the MCP stdio server.
//! The split exists so the Stage 1 simulated-device gate can link
//! the real protocol modules in an integration test instead of
//! re-implementing either side.

#![forbid(unsafe_code)]

pub mod apns;
pub mod approval;
pub mod backend;
pub mod capability;
pub mod catalog;
pub mod config;
pub mod gate;
pub mod guard;
pub mod mdm;
pub mod mdmhttp;
pub mod mdmstate;
pub mod plist;
pub mod profile;
pub mod scep;
pub mod server;
pub mod store;
