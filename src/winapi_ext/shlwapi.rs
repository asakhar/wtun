use winapi::shared::ntdef::{LPCWSTR, LPWSTR};

extern "system" {
  pub fn PathFindFileNameW(pszPath: LPCWSTR) -> LPWSTR;
}