use cutils::{inspection::GetPtrExt, set_last_error, strings::WideCString, widecstr, widecstring, csizeof};
use winapi::shared::{
  minwindef::{DWORD, HKEY, ULONG},
  ntdef::{NTSTATUS, NT_SUCCESS, WCHAR},
};

use crate::{
  ntdll::{NtQueryKey, KEY_NAME_INFORMATION},
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

fn LoggerGetRegistryKeyPathImpl(Key: HKEY) -> WideCString {
  if Key.is_null() {
    return widecstr!("<null>").to_owned();
  }
  let error_case_ret = widecstring!("0x{:p}", Key);
  let mut KeyNameInfo: KEY_NAME_INFORMATION = KEY_NAME_INFORMATION {
    NameLength: 0,
    Name: [0; MAX_REG_PATH],
  };
  let mut Size: DWORD = 0;
  if NT_SUCCESS(unsafe {
    NtQueryKey(
      Key.cast(),
      3,
      KeyNameInfo.get_mut_ptr() as *mut _,
      csizeof!(KEY_NAME_INFORMATION),
      Size.get_mut_ptr(),
    )
  } as NTSTATUS)
  {
    return error_case_ret;
  }
  if (Size as usize) < KEY_NAME_INFORMATION::OFFSETOF_NAME
    || KeyNameInfo.NameLength as usize >= MAX_REG_PATH * csizeof!(WCHAR; usize)
  {
    return error_case_ret;
  }
  KeyNameInfo.NameLength /= csizeof!(WCHAR; ULONG);
  unsafe { WideCString::from_ptr_n(KeyNameInfo.Name.as_ptr(), KeyNameInfo.NameLength as usize) }
    .unwrap_or(error_case_ret)
}

pub fn LoggerGetRegistryKeyPath(Key: &RegKey) -> WideCString {
  let LastError = std::io::Error::last_os_error();
  let res = LoggerGetRegistryKeyPathImpl(Key.as_raw());
  set_last_error(LastError);
  res
}
