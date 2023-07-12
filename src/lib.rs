#![allow(dead_code, unused_unsafe)]
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
use winapi::shared::minwindef::ULONG;

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
mod session;

pub use adapter::Adapter;
pub use logger::{set_logger, LogLevel};
pub use driver::get_running_driver_version;

pub const MIN_RING_CAPACITY: ULONG = 0x20000;
pub const MAX_RING_CAPACITY: ULONG = 0x4000000;
pub const MAX_IP_PACKET_SIZE: ULONG = 0xFFFF;
