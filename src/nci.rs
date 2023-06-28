use cutils::{strings::WideCStr, Win32Result, inspection::GetPtrExt, code_to_result};
use winapi::shared::{guiddef::GUID, ntdef::LPCWSTR, minwindef::DWORD};

extern "C" {
  fn NciSetConnectionName(Guid: *const GUID, NewName: LPCWSTR) -> DWORD;
}

pub fn SetConnectionName(Guid: GUID, NewName: &WideCStr) -> Win32Result<()> {
  let result = unsafe { NciSetConnectionName(Guid.get_const_ptr(), NewName.as_ptr()) };
  code_to_result(result)
}