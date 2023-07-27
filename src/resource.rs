use std::{
  io::Write,
  path::{Path, PathBuf},
};

use cutils::{files::get_windows_dir_path, ioeresult};
use rand::Rng;

use crate::logger::error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResId {
  CatX86,
  SysX86,
  InfX86,
  CatAmd64,
  SysAmd64,
  InfAmd64,
  CatArm,
  SysArm,
  InfArm,
  CatArm64,
  SysArm64,
  InfArm64,
  #[cfg(any(feature = "build_amd64_gnu_wow64", feature = "build_amd64_msvc_wow64"))]
  SetupApiHostAmd64,
  #[cfg(feature = "build_arm64_msvc_wow64")]
  SetupApiHostArm64,
}

pub fn copy_to_file(dst: &Path, id: ResId) -> std::io::Result<()> {
  const WINTUN_CAT_X86: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/driver-files/wintun-x86.cat"));
  const WINTUN_SYS_X86: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/driver-files/wintun-x86.sys"));
  const WINTUN_INF_X86: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/driver-files/wintun-x86.inf"));
  const WINTUN_CAT_AMD64: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/driver-files/wintun-amd64.cat"));
  const WINTUN_SYS_AMD64: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/driver-files/wintun-amd64.sys"));
  const WINTUN_INF_AMD64: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/driver-files/wintun-amd64.inf"));
  const WINTUN_CAT_ARM64: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/driver-files/wintun-arm64.cat"));
  const WINTUN_SYS_ARM64: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/driver-files/wintun-arm64.sys"));
  const WINTUN_INF_ARM64: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/driver-files/wintun-arm64.inf"));
  const WINTUN_CAT_ARM: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/driver-files/wintun-arm.cat"));
  const WINTUN_SYS_ARM: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/driver-files/wintun-arm.sys"));
  const WINTUN_INF_ARM: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/driver-files/wintun-arm.inf"));
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
  #[cfg(all(
    feature = "build_amd64_msvc_wow64",
    not(feature = "build_amd64_gnu_wow64")
  ))]
  const WINTUN_SETUP_API_HOST_AMD64: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/setupapihost/x86_64-pc-windows-msvc/",
    toggle_release!(),
    "setupapihost.dll"
  ));
  #[cfg(all(
    feature = "build_amd64_gnu_wow64",
    not(feature = "build_amd64_msvc_wow64")
  ))]
  const WINTUN_SETUP_API_HOST_AMD64: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/setupapihost/x86_64-pc-windows-gnu/",
    toggle_release!(),
    "setupapihost.dll"
  ));
  #[cfg(all(feature = "build_amd64_gnu_wow64", feature = "build_amd64_msvc_wow64"))]
  compile_error!(
    "Disable one of the features: 'build_amd64_gnu_wow64' or 'build_amd64_msvc_wow64'"
  );

  #[cfg(feature = "build_arm64_msvc_wow64")]
  const WINTUN_SETUP_API_HOST_ARM64: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/setupapihost/aarch64-pc-windows-msvc/",
    toggle_release!(),
    "setupapihost.dll"
  ));

  let resource = match id {
    ResId::CatX86 => WINTUN_CAT_X86,
    ResId::SysX86 => WINTUN_SYS_X86,
    ResId::InfX86 => WINTUN_INF_X86,
    ResId::CatAmd64 => WINTUN_CAT_AMD64,
    ResId::SysAmd64 => WINTUN_SYS_AMD64,
    ResId::InfAmd64 => WINTUN_INF_AMD64,
    ResId::CatArm => WINTUN_CAT_ARM,
    ResId::SysArm => WINTUN_SYS_ARM,
    ResId::InfArm => WINTUN_INF_ARM,
    ResId::CatArm64 => WINTUN_CAT_ARM64,
    ResId::SysArm64 => WINTUN_SYS_ARM64,
    ResId::InfArm64 => WINTUN_INF_ARM64,
    #[cfg(any(feature = "build_amd64_gnu_wow64", feature = "build_amd64_msvc_wow64"))]
    ResId::SetupApiHostAmd64 => WINTUN_SETUP_API_HOST_AMD64,
    #[cfg(feature = "build_arm64_msvc_wow64")]
    ResId::SetupApiHostArm64 => WINTUN_SETUP_API_HOST_ARM64,
  };
  if resource.is_empty() {
    return ioeresult!(NotFound, "{id:?} is not present in library resources");
  }
  std::fs::File::create(dst)?.write_all(resource)?;
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
  std::fs::create_dir_all(&random_temp_sub_dir_path)?;
  Ok(random_temp_sub_dir_path)
}
