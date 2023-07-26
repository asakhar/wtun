#![feature(core_intrinsics)]
#![feature(fn_ptr_trait)]
use std::marker::FnPtr;
use std::path::Path;
use std::ptr::null_mut;
use std::time::Duration;

use libloading::Symbol;
use widestring::widecstr;
use winapi::shared::basetsd::DWORD64;
use winapi::shared::guiddef::GUID;
use winapi::shared::ntdef::{HANDLE, LPCWSTR};

type WintunCreateAdapterFunc =
  unsafe extern "C" fn(name: LPCWSTR, tun: LPCWSTR, guid: *const GUID) -> HANDLE;
type WintunLoggerCallback = unsafe extern "C" fn(level: i32, timestamp: DWORD64, msg: LPCWSTR);
type WintunSetLoggerFunc = unsafe extern "C" fn(new_logger: Option<WintunLoggerCallback>);

unsafe extern "C" fn logger(level: i32, timestamp: DWORD64, msg: LPCWSTR) {
  let level = match level {
    0 => "info",
    1 => "warn",
    2 => "error",
    _ => "unknown",
  };
  const SECS_SINCE_1610_01_01_UNTIL_UNIX_TIMESTAMP: u64 = 131487 * 3600 * 24;
  let diff = std::time::Duration::from_micros(timestamp) / 10
    - std::time::Duration::from_secs(SECS_SINCE_1610_01_01_UNTIL_UNIX_TIMESTAMP);
  let timestamp = std::time::SystemTime::UNIX_EPOCH + diff;
  let message = unsafe { widestring::WideCStr::from_ptr_str(msg) };
  println!("[{level}] {:?}: {}", timestamp, message.display())
}

fn main() {
  #[cfg(target_arch = "x86")]
  let dll = Path::new("dlls/x86/wintun.dll");
  #[cfg(target_arch = "x86_64")]
  let dll = Path::new("dlls/amd64/wintun.dll");
  #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
  let dll = {
    #[cfg(target_arch = "arm")]
    print!("Do you want to run arm([1]) or arm64(2)? >");
    #[cfg(target_arch = "aarch64")]
    print!("Do you want to run arm(1) or arm64([2])? >");
    let opt = loop {
      let mut buf = String::new();
      std::io::stdin().read_line(&mut buf).unwrap();
      match buf.chars().next() {
        Some('1') => break 0,
        Some('2') => break 1,
        None => {
          #[cfg(target_arch = "arm")]
          break 0;
          #[cfg(target_arch = "aarch64")]
          break 1;
        }
        _ => {},
      };
      println!("Try again");
    };
    const OPTS: [&str; 2] = ["dlls/arm/wintun.dll", "dlls/arm64/wintun.dll"];
    Path::new(OPTS[opt])
  };
  println!("Working on: {}", dll.display());
  let lib = unsafe { libloading::Library::new(dll).unwrap() };
  let wintun_create_adapter: Symbol<WintunCreateAdapterFunc> =
    unsafe { lib.get(b"WintunCreateAdapter\0") }.unwrap();
  let wintun_set_logger: Symbol<WintunSetLoggerFunc> =
    unsafe { lib.get(b"WintunSetLogger\0") }.unwrap();
  unsafe {
    wintun_set_logger(Some(logger));
  }
  println!("my id is: {}", std::process::id());
  println!("{:p}", wintun_create_adapter.addr());
  std::thread::sleep(Duration::from_secs(15));
  unsafe { std::intrinsics::breakpoint() };
  let adapter = unsafe {
    wintun_create_adapter(
      widecstr!("test").as_ptr(),
      widecstr!("test").as_ptr(),
      null_mut(),
    )
  };
  assert_ne!(adapter, null_mut());
}
