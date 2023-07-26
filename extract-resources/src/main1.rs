#![allow(unused)]
use std::path::Path;

use libloading::Symbol;
use widestring::widecstr;
use winapi::shared::basetsd::DWORD64;
use winapi::shared::guiddef::GUID;
use winapi::shared::minwindef::BOOL;
use winapi::shared::ntdef::LPCWSTR;

type ResourceCopyToFileFunc = unsafe extern "C" fn(dst: LPCWSTR, name: LPCWSTR) -> BOOL;
type WintunCreateAdapterFunc =
  unsafe extern "C" fn(name: LPCWSTR, tun: LPCWSTR, guid: *const GUID) -> BOOL;
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
  let resources = [
    widecstr!("wintun.sys"),
    widecstr!("wintun.cat"),
    widecstr!("wintun.inf"),
  ];
  let outputs = [
    widecstr!(r"output\wintun.sys"),
    widecstr!(r"output\wintun.cat"),
    widecstr!(r"output\wintun.inf"),
  ];
  let dll = Path::new("dlls/amd64/wintun.dll");
  println!("Working on: {}", dll.display());
  let lib = unsafe { libloading::Library::new(dll).unwrap() };
  let wintun_create_adapter: Symbol<WintunCreateAdapterFunc> =
    unsafe { lib.get(b"WintunCreateAdapter\0") }.unwrap();
  let wintun_set_logger: Symbol<WintunSetLoggerFunc> =
    unsafe { lib.get(b"WintunSetLogger\0") }.unwrap();
  unsafe {
    wintun_set_logger(Some(logger));
  }
  let adapter = unsafe { wintun_create_adapter(
    widecstr!("test").as_ptr(),
    widecstr!("test").as_ptr(),
    std::ptr::null_mut(),
  ) };
  assert_ne!(adapter, 0);
  // let wintun_extract_resource = unsafe { ((*wintun_create_adapter) as *const u8).add(0x2ee0) };
  // let wintun_extract_resource: ResourceCopyToFileFunc = unsafe { std::mem::transmute(wintun_extract_resource) };

  // for (output, resource) in outputs.iter().zip(resources) {
  //   unsafe { wintun_extract_resource(output.as_ptr(), resource.as_ptr()); }
  // }
}
