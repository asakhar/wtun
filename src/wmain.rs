use winapi::{
  shared::{minwindef::DWORD, ntdef::HANDLE},
  um::{minwinbase::SECURITY_ATTRIBUTES, },
};

use crate::winapi_ext::devquery::USHORT;

pub static mut ModuleHeap: HANDLE = std::ptr::null_mut();
pub static mut SecurityAttributes: SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES {
  nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as DWORD,
  lpSecurityDescriptor: std::ptr::null_mut(),
  bInheritHandle: 0,
};
pub static mut IsLocalSystem: bool = false;
#[cfg(target_arch = "x86")]
pub const IMAGE_FILE_PROCESS: USHORT = winapi::um::winnt::IMAGE_FILE_MACHINE_I386;
#[cfg(target_arch = "x86_64")]
pub const IMAGE_FILE_PROCESS: USHORT = winapi::um::winnt::IMAGE_FILE_MACHINE_AMD64;
#[cfg(target_arch = "arm")]
pub const IMAGE_FILE_PROCESS: USHORT = winapi::um::winnt::IMAGE_FILE_MACHINE_ARMNT;
#[cfg(target_arch = "aarch64")]
pub const IMAGE_FILE_PROCESS: USHORT = winapi::um::winnt::IMAGE_FILE_MACHINE_ARM64;
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm", target_arch = "aarch64")))]
compile_error!("Unsupported architecture");
pub static mut NativeMachine: USHORT = IMAGE_FILE_PROCESS;
