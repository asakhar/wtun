use winapi::shared::ntdef::{LPCWSTR, LPWSTR};

extern "system" {
  pub(crate) fn PathFindFileNameW(pszPath: LPCWSTR) -> LPWSTR;
}