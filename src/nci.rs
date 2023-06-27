use widestring::WideCStr;
use winapi::shared::{guiddef::GUID, ntdef::LPCWSTR, minwindef::DWORD};

use crate::{utils::{Win32Result, GetPtrExt, code_to_result}};

extern "C" {
  fn NciSetConnectionName(Guid: *const GUID, NewName: LPCWSTR) -> DWORD;
}

pub fn SetConnectionName(Guid: GUID, NewName: &WideCStr) -> Win32Result<()> {
  let result = unsafe { NciSetConnectionName(Guid.get_const_ptr(), NewName.as_ptr()) };
  code_to_result(result)
}