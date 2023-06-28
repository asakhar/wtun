use std::{
  io::Write,
  path::{Path, PathBuf},
};

use cutils::{Win32Result, strings::WideCStr};
use get_last_error::Win32Error;
use rand::Rng;
use winapi::{
  shared::{minwindef::MAX_PATH, ntdef::WCHAR},
  um::sysinfoapi::GetWindowsDirectoryW,
};

use crate::logger::last_error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResId {
  Cat,
  Sys,
  Inf,
}

pub fn copy_to_file(dst: &Path, id: ResId) -> Win32Result<()> {
  const WINTUN_CAT: &[u8] = include_bytes!("driver-files/wintun.cat");
  const WINTUN_SYS: &[u8] = include_bytes!("driver-files/wintun.sys");
  const WINTUN_INF: &[u8] = include_bytes!("driver-files/wintun.inf");
  let resource = match id {
    ResId::Cat => WINTUN_CAT,
    ResId::Sys => WINTUN_SYS,
    ResId::Inf => WINTUN_INF,
  };
  std::fs::File::create(dst)
    .as_ref()
    .map_err(std::io::Error::raw_os_error)
    .map_err(Option::unwrap)
    .map_err(|e| e as u32)
    .map_err(Win32Error::new)?
    .write_all(resource)
    .as_ref()
    .map_err(std::io::Error::raw_os_error)
    .map_err(Option::unwrap)
    .map_err(|e| e as u32)
    .map_err(Win32Error::new)?;
  Ok(())
}

pub fn create_temp_dir() -> Win32Result<PathBuf> {
  let mut windows_directory = [0 as WCHAR; MAX_PATH];
  let result = unsafe { GetWindowsDirectoryW(windows_directory.as_mut_ptr(), MAX_PATH as u32) };
  if result == 0 {
    let err = last_error!("Failed to get Windows folder");
    return Err(err.into());
  }
  let windows_dir = unsafe { WideCStr::from_ptr(windows_directory.as_ptr()) };
  let windows_dir = windows_dir.to_os_string();
  let windows_dir_path = Path::new(&windows_dir);
  let temp_path = windows_dir_path.join("Temp");
  const HEX: [char; 16] = b"0123456789ABCDEF".map(|c| c as char);
  let hex_dist = rand::distributions::Slice::new(&HEX).unwrap();
  let random_hex_string: String = rand::thread_rng().sample_iter(&hex_dist).take(32).collect();
  let random_temp_sub_dir_path = temp_path.join(random_hex_string);
  // TODO: std::fs::set_permissions(path, perm)
  std::fs::create_dir_all(&random_temp_sub_dir_path)
    .as_ref()
    .map_err(std::io::Error::raw_os_error)
    .map_err(Option::unwrap)
    .map_err(|e| e as u32)
    .map_err(Win32Error::new)?;
  Ok(random_temp_sub_dir_path)
}
