use cutils::{
  csizeof, inspection::GetPtrExt, set_last_error, strings::WideCString, widecstr, widecstring,
};
use winapi::shared::{
  minwindef::{DWORD, HKEY, ULONG},
  ntdef::{NTSTATUS, NT_SUCCESS, WCHAR},
};

use crate::{
  ntdll::{KeyNameInformation, NtQueryKey},
  registry::{RegKey, MAX_REG_PATH},
};

pub use log::Level;

pub trait IntoError {
  fn into_error(self) -> std::io::Error;
}

impl IntoError for std::io::Error {
  fn into_error(self) -> std::io::Error {
    self
  }
}

impl IntoError for u32 {
  fn into_error(self) -> std::io::Error {
    std::io::Error::from_raw_os_error(self as i32)
  }
}

impl IntoError for i32 {
  fn into_error(self) -> std::io::Error {
    std::io::Error::from_raw_os_error(self)
  }
}

mod macro_impl {
  macro_rules! error {
    ($error:expr, $fmt:literal $(,$args:expr)*) => {
      {
        {
          use $crate::logger::IntoError;
          let error: ::std::io::Error = $error.into_error();
          log::error!("{}: {} (Code 0x{:08X})", format_args!($fmt $(,$args)*), error, error.raw_os_error().unwrap_or(0));
          error
        }
      }
    };
  }

  macro_rules! last_error {
    ($fmt:literal $(,$args:expr)*) => {
      {
        let last_error = std::io::Error::last_os_error();
        log::error!("{}: {} (Code 0x{:08X})", format_args!($fmt $(,$args)*), last_error, last_error.raw_os_error().unwrap_or(0));
        last_error
      }
    };
  }
  pub(crate) use error;
  pub(crate) use last_error;
  pub(crate) use log::info;
  pub(crate) use log::log;
  pub(crate) use log::warn;
}

pub(crate) use macro_impl::error;
pub(crate) use macro_impl::info;
pub(crate) use macro_impl::last_error;
pub(crate) use macro_impl::log;
pub(crate) use macro_impl::warn;

fn logger_get_registry_key_path_impl(key: HKEY) -> WideCString {
  if key.is_null() {
    return widecstr!("<null>").to_owned();
  }
  let error_case_ret = widecstring!("0x{:p}", key);
  let mut key_name_info: KeyNameInformation = KeyNameInformation {
    name_length: 0,
    name: [0; MAX_REG_PATH],
  };
  let mut size: DWORD = 0;
  if NT_SUCCESS(unsafe {
    NtQueryKey(
      key.cast(),
      3,
      key_name_info.get_mut_ptr() as *mut _,
      csizeof!(KeyNameInformation),
      size.get_mut_ptr(),
    )
  } as NTSTATUS)
  {
    return error_case_ret;
  }
  if (size as usize) < KeyNameInformation::OFFSETOF_NAME
    || key_name_info.name_length as usize >= MAX_REG_PATH * csizeof!(WCHAR; usize)
  {
    return error_case_ret;
  }
  key_name_info.name_length /= csizeof!(WCHAR; ULONG);
  unsafe {
    WideCString::from_ptr_n(
      key_name_info.name.as_ptr(),
      key_name_info.name_length as usize,
    )
  }
  .unwrap_or(error_case_ret)
}

pub fn logger_get_registry_key_path(key: &RegKey) -> WideCString {
  let last_error = std::io::Error::last_os_error();
  let res = logger_get_registry_key_path_impl(key.as_raw());
  set_last_error(last_error);
  res
}
