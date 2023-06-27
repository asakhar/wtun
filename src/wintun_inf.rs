use winapi::shared::{
  minwindef::{DWORD, FILETIME},
  ntdef::DWORDLONG,
};

pub const WINTUN_INF_FILETIME: FILETIME = FILETIME {
  dwLowDateTime: ((16860096000000000u64 + 116444736000000000u64) & 0xffffffff) as DWORD,
  dwHighDateTime: ((16860096000000000u64 + 116444736000000000u64) >> 32) as DWORD,
};
pub const WINTUN_INF_VERSION: DWORDLONG = (12 << 48) | (50 << 32) | (58 << 16) | (92 << 0);
