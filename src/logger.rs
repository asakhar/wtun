use std::{mem::size_of, time::SystemTime};

use cutils::{
  ignore::ResultIgnoreExt,
  inspection::{CastToMutVoidPtrExt, GetPtrExt},
  set_last_error,
  strings::WideCString,
  widecstr, widecstring,
};
use get_last_error::Win32Error;
use winapi::shared::{
  minwindef::{DWORD, HKEY, ULONG},
  ntdef::{NTSTATUS, NT_SUCCESS, WCHAR},
};

use crate::{
  ntdll::{NtQueryKey, KEY_NAME_INFORMATION},
  registry::{RegKey, MAX_REG_PATH},
};

/**
 * Determines the level of logging, passed to WINTUN_LOGGER_CALLBACK.
 */
pub enum LogLevel {
  Info,
  Warning,
  Error,
}

/**
 * Called by internal logger to report diagnostic messages
 *
 * @param Level         Message level.
 *
 * @param Timestamp     Message timestamp in in 100ns intervals since 1601-01-01 UTC.
 *
 * @param Message       Message text.
 */
pub type LoggerCallback = fn(Level: LogLevel, Timestamp: SystemTime, Message: core::fmt::Arguments);
pub static WINTUN_LOGGER: Logger = Logger::new();
pub struct Logger {
  logger: std::sync::RwLock<LoggerCallback>,
}

pub trait IntoError {
  fn into_error(self) -> std::io::Error;
}

impl IntoError for Win32Error {
  fn into_error(self) -> std::io::Error {
    std::io::Error::from_raw_os_error(self.code() as i32)
  }
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

impl Logger {
  const fn new() -> Self {
    Self {
      logger: std::sync::RwLock::new(NopLogger),
    }
  }
  pub fn log(&self, level: LogLevel, log_line: core::fmt::Arguments) {
    self.logger.read().ignore()(level, SystemTime::now(), format_args!("{}", log_line));
  }
  pub fn error(&self, Error: impl IntoError, Prefix: core::fmt::Arguments) -> std::io::Error {
    let error = Error.into_error();
    let code = match error.raw_os_error() {
      Some(err) => format_args!("(Code 0x{err:08X})"),
      None => format_args!(""),
    };
    let msg = format_args!("{}: {} {}", Prefix, error, code);
    self.logger.read().ignore()(LogLevel::Error, SystemTime::now(), msg);
    error
  }
}

pub fn set_logger(new_logger: LoggerCallback) -> LoggerCallback {
  std::mem::replace(&mut WINTUN_LOGGER.logger.write().ignore(), new_logger)
}

mod macro_impl {

  macro_rules! log {
    ($level:expr, $fmt:literal, $($args:expr),*) => {
      {
        let log_line = format_args!($fmt, $($args),*);
        $crate::logger::WINTUN_LOGGER.log($level, log_line)
      }
    };
    ($level:expr, $fmt:literal) => {
      {
        $crate::logger::WINTUN_LOGGER.log($level, format_args!($fmt))
      }
    };
  }

  macro_rules! info {
    ($fmt:literal, $($args:expr),*) => {
      {
        let log_line = format_args!($fmt, $($args),*);
        $crate::logger::WINTUN_LOGGER.log($crate::logger::LogLevel::Info, log_line)
      }
    };
    ($fmt:literal) => {
      {
        $crate::logger::WINTUN_LOGGER.log($crate::logger::LogLevel::Info, format_args!($fmt))
      }
    };
  }

  macro_rules! warning {
    ($fmt:literal, $($args:expr),*) => {
      {
        let log_line = format_args!($fmt, $($args),*);
        $crate::logger::WINTUN_LOGGER.log($crate::logger::LogLevel::Warning, &log_line)
      }
    };
    ($fmt:literal) => {
      {
        $crate::logger::WINTUN_LOGGER.log($crate::logger::LogLevel::Warning, format_args!($fmt))
      }
    };
  }

  macro_rules! error {
    ($error:expr, $fmt:literal, $($args:expr),*) => {
      {
        let log_line = format_args!($fmt, $($args),*);
        $crate::logger::WINTUN_LOGGER.error($error, log_line)
      }
    };
    ($error:expr, $fmt:literal) => {
      {
        $crate::logger::WINTUN_LOGGER.error($error, format_args!($fmt))
      }
    };
  }

  macro_rules! last_error {
    ($fmt:literal, $($args:expr),*) => {
      {
        let last_error = std::io::Error::last_os_error();
        let res = $crate::logger::error!(last_error, $fmt, $($args),*);
        res
      }
    };
    ($fmt:literal) => {
      {
        let last_error = std::io::Error::last_os_error();
        let res = $crate::logger::error!(last_error, $fmt);
        res
      }
    };
  }
  pub(crate) use error;
  pub(crate) use info;
  pub(crate) use last_error;
  pub(crate) use log;
  pub(crate) use warning;
}

pub(crate) use macro_impl::error;
pub(crate) use macro_impl::info;
pub(crate) use macro_impl::last_error;
pub(crate) use macro_impl::log;
pub(crate) use macro_impl::warning as warn;

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
      Key.cast_to_pvoid(),
      3,
      KeyNameInfo.get_mut_ptr() as *mut _,
      size_of::<KEY_NAME_INFORMATION>() as ULONG,
      Size.get_mut_ptr(),
    )
  } as NTSTATUS)
  {
    return error_case_ret;
  }
  if (Size as usize) < KEY_NAME_INFORMATION::OFFSETOF_NAME
    || KeyNameInfo.NameLength as usize >= MAX_REG_PATH * size_of::<WCHAR>()
  {
    return error_case_ret;
  }
  KeyNameInfo.NameLength /= size_of::<WCHAR>() as u32;
  unsafe { WideCString::from_ptr_n(KeyNameInfo.Name.as_ptr(), KeyNameInfo.NameLength as usize) }
    .unwrap_or(error_case_ret)
}

pub fn LoggerGetRegistryKeyPath(Key: &RegKey) -> WideCString {
  let LastError = get_last_error::Win32Error::get_last_error();
  let res = LoggerGetRegistryKeyPathImpl(Key.as_raw());
  set_last_error(LastError);
  res
}

// pub fn LoggerAlloc(function: &str, Flags: DWORD, Size: size_t) -> std::io::Result<PVOID> {
//   let Data = unsafe { HeapAlloc(ModuleHeap, Flags, Size) };
//   if Data.is_null() {
//     set_last_error(Win32Error::new(ERROR_OUTOFMEMORY));
//     return Err(last_error!(
//       "Out of memory (flags: 0x{:x}, requested size: 0x{:x}, function: {})",
//       Flags,
//       Size,
//       function
//     ));
//   }
//   Ok(Data)
// }

// pub fn LoggerReAlloc(
//   function: &str,
//   Flags: DWORD,
//   Mem: LPVOID,
//   Size: size_t,
// ) -> std::io::Result<PVOID> {
//   let Data = if Mem.is_null() {
//     unsafe { HeapReAlloc(ModuleHeap, Flags, Mem, Size) }
//   } else {
//     unsafe { HeapAlloc(ModuleHeap, Flags, Size) }
//   };
//   if Data.is_null() {
//     set_last_error(Win32Error::new(ERROR_OUTOFMEMORY));
//     return Err(last_error!(
//       "Out of memory (flags: 0x{:x}, requested size: 0x{:x}, function: {})",
//       Flags,
//       Size,
//       function
//     ));
//   }
//   Ok(Data)
// }

// #[macro_export]
// macro_rules! Alloc {
//   ($size:expr) => {
//     $crate::logger::LoggerAlloc($crate::function!(), 0, $size)
//   };
// }

// #[macro_export]
// macro_rules! ReAlloc {
//   ($mem:expr, $size:expr) => {
//     use $crate::utils::CastToMutVoidPtrExt;
//     $crate::logger::LoggerReAlloc($crate::function!(), 0, ($mem).cast_to_pvoid(), $size)
//   };
// }

// #[macro_export]
// macro_rules! Zalloc {
//   ($size:expr) => {
//     $crate::logger::LoggerAlloc(
//       $crate::function!(),
//       winapi::um::winnt::HEAP_ZERO_MEMORY,
//       $size,
//     )
//   };
// }

// #[macro_export]
// macro_rules! ReZalloc {
//   ($mem:expr, $size:expr) => {
//     use $crate::utils::CastToMutVoidPtrExt;
//     $crate::logger::LoggerReAlloc(
//       $crate::function!(),
//       winapi::um::winnt::HEAP_ZERO_MEMORY,
//       ($mem).cast_to_pvoid(),
//       $size,
//     )
//   };
// }

// pub fn LoggerAllocArray(
//   function: &str,
//   Flags: DWORD,
//   NumberOfElements: size_t,
//   SizeOfOneElement: size_t,
// ) -> std::io::Result<PVOID> {
//   let Size = NumberOfElements
//     .checked_mul(SizeOfOneElement)
//     .ok_or(Win32Error::new(ERROR_INVALID_PARAMETER))?;

//   LoggerAlloc(function, Flags, Size)
// }

// pub fn LoggerReAllocArray(
//   function: &str,
//   Flags: DWORD,
//   Mem: LPVOID,
//   NumberOfElements: size_t,
//   SizeOfOneElement: size_t,
// ) -> std::io::Result<PVOID> {
//   let Size = NumberOfElements
//     .checked_mul(SizeOfOneElement)
//     .ok_or(Win32Error::new(ERROR_INVALID_PARAMETER))?;

//   LoggerReAlloc(function, Flags, Mem, Size)
// }

// #[macro_export]
// macro_rules! AllocArray {
//   ($count:expr, $size:expr) => {
//     $crate::logger::LoggerAllocArray($crate::function!(), 0, $count, $size)
//   };
// }

// #[macro_export]
// macro_rules! ReAllocArray {
//   ($mem:expr, $count:expr, $size:expr) => {
//     use $crate::utils::CastToMutVoidPtrExt;
//     $crate::logger::LoggerReAllocArray(
//       $crate::function!(),
//       0,
//       ($mem).cast_to_pvoid(),
//       $count,
//       $size,
//     )
//   };
// }

// #[macro_export]
// macro_rules! ZallocArray {
//   ($count:expr, $size:expr) => {
//     $crate::logger::LoggerAllocArray(
//       $crate::function!(),
//       winapi::um::winnt::HEAP_ZERO_MEMORY,
//       $count,
//       $size,
//     )
//   };
// }

// #[macro_export]
// macro_rules! ReZallocArray {
//   ($mem:expr, $count:expr, $size:expr) => {{
//     use $crate::utils::CastToMutVoidPtrExt;
//     $crate::logger::LoggerReAllocArray(
//       $crate::function!(),
//       winapi::um::winnt::HEAP_ZERO_MEMORY,
//       ($mem).cast_to_pvoid(),
//       $count,
//       $size,
//     )
//   }};
// }

// pub fn Free(Ptr: LPVOID) {
//   if Ptr.is_null() {
//     return;
//   }
//   let LastError = Win32Error::get_last_error();
//   unsafe { HeapFree(ModuleHeap, 0, Ptr) };
//   set_last_error(LastError);
// }

fn NopLogger(_Level: LogLevel, _Timestamp: SystemTime, _LogLine: core::fmt::Arguments) {}
