use cutils::{strings::WideCStr, inspection::GetPtrExt, code_to_result};
use winapi::shared::{guiddef::GUID, ntdef::LPCWSTR, minwindef::DWORD};

unsafe extern "C" fn NciSetConnectionName(_Guid: *const GUID, _NewName: LPCWSTR) -> DWORD {
  return 0;
}

pub fn SetConnectionName(Guid: GUID, NewName: &WideCStr) -> std::io::Result<()> {
  let result = unsafe { NciSetConnectionName(Guid.get_const_ptr(), NewName.as_ptr()) };
  code_to_result(result)
}