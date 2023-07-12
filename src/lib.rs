#![allow(dead_code)]
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
mod adapter;
mod adapter_win7;
mod logger;
mod ntdll;
mod registry;
mod wmain;
mod namespace;
mod nci;
mod winapi_ext;
mod driver;
mod wintun_inf;
mod resource;
mod rundll32;

pub use adapter::Adapter;
pub use logger::{set_logger, LogLevel};