use winapi::shared::ntdef::{LPCWSTR, LPWSTR};

extern "C" {
  pub fn PathFindFileNameW(pszPath: LPCWSTR) -> LPWSTR;
}