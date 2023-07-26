#![feature(fn_ptr_trait)]
use std::collections::BTreeSet;
use std::marker::FnPtr;
use std::path::Path;

use libloading::Symbol;
use widestring::widecstr;
use winapi::shared::basetsd::DWORD64;
use winapi::shared::guiddef::GUID;
use winapi::shared::minwindef::BOOL;
use winapi::shared::ntdef::LPCWSTR;
#[cfg(target_arch = "x86")]
macro_rules! ResourceCopyToFileFunc_define {
  () => {
    type ResourceCopyToFileFunc = unsafe extern "fastcall" fn(dst: LPCWSTR, name: LPCWSTR) -> BOOL;
  };
}
#[cfg(target_arch = "x86_64")]
macro_rules! ResourceCopyToFileFunc_define {
  () => {
    type ResourceCopyToFileFunc = unsafe extern "C" fn(dst: LPCWSTR, name: LPCWSTR) -> BOOL;
  };
}
ResourceCopyToFileFunc_define!();
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
  const SECS_SINCE_1610_01_01_UNTIL_UNIX_TIMESTAMP: u64 = (131487 + 365 * 9 + 2) * 3600 * 24;
  let diff = std::time::Duration::from_micros(timestamp) / 10
    - std::time::Duration::from_secs(SECS_SINCE_1610_01_01_UNTIL_UNIX_TIMESTAMP);
  let timestamp = std::time::SystemTime::UNIX_EPOCH + diff;
  let timestamp: chrono::DateTime<chrono::Local> = timestamp.into();
  let message = unsafe { widestring::WideCStr::from_ptr_str(msg) };
  println!(
    "[{level}] {}: {}",
    timestamp.format("%d.%m.%Y %T"),
    message.display()
  )
}

fn main() {
  let resources = [
    widecstr!("wintun.sys"),
    widecstr!("wintun.cat"),
    widecstr!("wintun.inf"),
    widecstr!("wintun-amd64.sys"),
    widecstr!("wintun-amd64.cat"),
    widecstr!("wintun-amd64.inf"),
    widecstr!("wintun-arm64.sys"),
    widecstr!("wintun-arm64.cat"),
    widecstr!("wintun-arm64.inf"),
  ];
  #[cfg(target_arch = "x86_64")]
  let outputs = [
    widecstr!(r"output\amd64\wintun-amd64.sys"),
    widecstr!(r"output\amd64\wintun-amd64.cat"),
    widecstr!(r"output\amd64\wintun-amd64.inf"),
    widecstr!(r"output\amd64\wintun-amd64.sys"),
    widecstr!(r"output\amd64\wintun-amd64.cat"),
    widecstr!(r"output\amd64\wintun-amd64.inf"),
    widecstr!(r"output\amd64\wintun-arm64.sys"),
    widecstr!(r"output\amd64\wintun-arm64.cat"),
    widecstr!(r"output\amd64\wintun-arm64.inf"),
  ];
  #[cfg(target_arch = "x86")]
  let outputs = [
    widecstr!(r"output\x86\wintun-x86.sys"),
    widecstr!(r"output\x86\wintun-x86.cat"),
    widecstr!(r"output\x86\wintun-x86.inf"),
    widecstr!(r"output\x86\wintun-amd64.sys"),
    widecstr!(r"output\x86\wintun-amd64.cat"),
    widecstr!(r"output\x86\wintun-amd64.inf"),
    widecstr!(r"output\x86\wintun-arm64.sys"),
    widecstr!(r"output\x86\wintun-arm64.cat"),
    widecstr!(r"output\x86\wintun-arm64.inf"),
  ];
  #[cfg(target_arch = "arm")]
  let outputs = [
    widecstr!(r"output\arm\wintun-arm.sys"),
    widecstr!(r"output\arm\wintun-arm.cat"),
    widecstr!(r"output\arm\wintun-arm.inf"),
    widecstr!(r"output\arm\wintun-amd64.sys"),
    widecstr!(r"output\arm\wintun-amd64.cat"),
    widecstr!(r"output\arm\wintun-amd64.inf"),
    widecstr!(r"output\arm\wintun-arm64.sys"),
    widecstr!(r"output\arm\wintun-arm64.cat"),
    widecstr!(r"output\arm\wintun-arm64.inf"),
  ];
  #[cfg(target_arch = "aarch64")]
  let outputs = [
    widecstr!(r"output\arm64\wintun-arm64.sys"),
    widecstr!(r"output\arm64\wintun-arm64.cat"),
    widecstr!(r"output\arm64\wintun-arm64.inf"),
    widecstr!(r"output\arm64\wintun-amd64.sys"),
    widecstr!(r"output\arm64\wintun-amd64.cat"),
    widecstr!(r"output\arm64\wintun-amd64.inf"),
    widecstr!(r"output\arm64\wintun-arm64.sys"),
    widecstr!(r"output\arm64\wintun-arm64.cat"),
    widecstr!(r"output\arm64\wintun-arm64.inf"),
  ];
  #[cfg(target_arch = "x86")]
  let dll = Path::new("dlls/x86/wintun.dll");
  #[cfg(target_arch = "x86_64")]
  let dll = Path::new("dlls/amd64/wintun.dll");
  #[cfg(target_arch = "arm")]
  let dll = Path::new("dlls/arm/wintun.dll");
  #[cfg(target_arch = "aarch64")]
  let dll = Path::new("dlls/arm64/wintun.dll");
  println!("Working on: {}", dll.display());
  let lib = unsafe { libloading::Library::new(dll).unwrap() };
  let wintun_create_adapter: Symbol<WintunCreateAdapterFunc> =
    unsafe { lib.get(b"WintunCreateAdapter\0") }.unwrap();
  let wintun_set_logger: Symbol<WintunSetLoggerFunc> =
    unsafe { lib.get(b"WintunSetLogger\0") }.unwrap();
  println!("my id is: {}", std::process::id());
  unsafe {
    wintun_set_logger(Some(logger));
  }
  println!("create adapter ptr: {:p}", wintun_create_adapter.addr());
  #[cfg(target_arch = "x86")]
  let offset = 0x2cc0;
  #[cfg(target_arch = "x86_64")]
  let offset = 0x2ee0;
  #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
  compile_error!("Architecture is not supported yet");
  let wintun_extract_resource = unsafe { ((*wintun_create_adapter) as *const u8).add(offset) };
  let wintun_extract_resource: ResourceCopyToFileFunc =
    unsafe { std::mem::transmute(wintun_extract_resource) };
  println!("function ptr: {:p}", wintun_extract_resource);
  println!("Cleaning up output directory...");
  #[cfg(target_arch = "x86_64")] {
    drop(std::fs::remove_dir_all("./output/amd64"));
    std::fs::create_dir_all("./output/amd64").unwrap();
  }
  #[cfg(target_arch = "x86")] {
    drop(std::fs::remove_dir_all("./output/x86"));
    std::fs::create_dir_all("./output/x86").unwrap();
  }
  #[cfg(target_arch = "arm")] {
    drop(std::fs::remove_dir_all("./output/arm"));
    std::fs::create_dir_all("./output/arm").unwrap();
  }
  #[cfg(target_arch = "aarch64")] {
    drop(std::fs::remove_dir_all("./output/arm64"));
    std::fs::create_dir_all("./output/arm64").unwrap();
  }
  let mut already_extracted = BTreeSet::new();
  for (output, resource) in outputs.iter().copied().zip(resources) {
    if already_extracted.insert(output) {
      println!("Extracting {} to {}", resource.display(), output.display());
      unsafe {
        wintun_extract_resource(output.as_ptr(), resource.as_ptr());
      }
    }
  }
  std::process::exit(0);
}
