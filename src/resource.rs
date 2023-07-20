use std::{
  io::Write,
  path::{Path, PathBuf},
};

use cutils::files::get_windows_dir_path;
use get_last_error::Win32Error;
use rand::Rng;

use crate::logger::error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResId {
  Cat,
  Sys,
  Inf,
  SetupApiHost,
}

pub fn copy_to_file(dst: &Path, id: ResId) -> std::io::Result<()> {
  const WINTUN_CAT: &[u8] = include_bytes!("driver-files/wintun.cat");
  const WINTUN_SYS: &[u8] = include_bytes!("driver-files/wintun.sys");
  const WINTUN_INF: &[u8] = include_bytes!("driver-files/wintun.inf");
  #[cfg(not(debug_assertions))]
  macro_rules! toggle_release {
    () => {
      "release/"
    };
  }
  #[cfg(debug_assertions)]
  macro_rules! toggle_release {
    () => {
      "debug/"
    };
  }
  const WINTUN_SETUP_API_HOST: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/setupapihost/",
    toggle_release!(),
    "setupapihost.dll"
  ));
  let resource = match id {
    ResId::Cat => WINTUN_CAT,
    ResId::Sys => WINTUN_SYS,
    ResId::Inf => WINTUN_INF,
    ResId::SetupApiHost => WINTUN_SETUP_API_HOST,
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

pub fn create_temp_dir() -> std::io::Result<PathBuf> {
  let windows_dir_path = match get_windows_dir_path() {
    Ok(res) => res,
    Err(err) => return Err(error!(err, "Failed to get Windows folder")),
  };
  let temp_path = windows_dir_path.join("Temp");
  const HEX: [u8; 16] = *b"0123456789ABCDEF";
  let hex_dist = rand::distributions::Slice::new(&HEX).unwrap();
  let random_hex_string: String = rand::thread_rng()
    .sample_iter(&hex_dist)
    .take(32)
    .map(|c| *c as char)
    .collect();
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
