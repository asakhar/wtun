use cutils::{strings::WideCStr, inspection::GetPtrExt, code_to_result};
use winapi::shared::{guiddef::GUID, ntdef::LPCWSTR, minwindef::DWORD};

unsafe extern "C" fn nci_set_connection_name(_guid: *const GUID, _new_name: LPCWSTR) -> DWORD {
  return 0;
}

pub fn set_connection_name(guid: GUID, new_name: &WideCStr) -> std::io::Result<()> {
  let result = unsafe { nci_set_connection_name(guid.get_const_ptr(), new_name.as_ptr()) };
  code_to_result(result)
}