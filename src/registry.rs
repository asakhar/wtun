use cutils::{
  check_handle,
  inspection::GetPtrExt,
  strings::{WideCStr, WideCString}, csizeof, ioeresult,
};
use winapi::{
  shared::{
    minwindef::{BYTE, DWORD, HKEY},
    ntdef::WCHAR,
    winerror::{ERROR_INVALID_DATA, ERROR_INVALID_DATATYPE, ERROR_MORE_DATA, ERROR_SUCCESS},
  },
  um::{
    processenv::ExpandEnvironmentStringsW,
    setupapi::{SetupDiOpenDevRegKey, HDEVINFO, PSP_DEVINFO_DATA},
    winnt::{REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ},
    winreg::{RegCloseKey, RegQueryValueExW, REGSAM},
  },
};

use crate::logger::{error, last_error, logger_get_registry_key_path};

/* Maximum registry path length
https://support.microsoft.com/en-us/help/256986/windows-registry-information-for-advanced-users */
pub const MAX_REG_PATH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RegistryValueType {
  RegExpandSz = REG_EXPAND_SZ,
  RegSz = REG_SZ,
}

impl TryFrom<DWORD> for RegistryValueType {
  type Error = DWORD;
  fn try_from(value: DWORD) -> Result<Self, Self::Error> {
    match value {
      REG_SZ | REG_MULTI_SZ => Ok(Self::RegSz),
      REG_EXPAND_SZ => Ok(Self::RegExpandSz),
      _ => Err(value),
    }
  }
}

#[derive(Debug)]
pub struct RegKey(HKEY);

impl RegKey {
  pub fn open(
    device_info_set: HDEVINFO,
    device_info_data: PSP_DEVINFO_DATA,
    scope: DWORD,
    hw_profile: DWORD,
    key_type: DWORD,
    sam_desired: REGSAM,
  ) -> std::io::Result<Self> {
    let key: HKEY = unsafe {
      SetupDiOpenDevRegKey(
        device_info_set,
        device_info_data,
        scope,
        hw_profile,
        key_type,
        sam_desired,
      )
    };
    if !check_handle(key.cast()) {
      return Err(last_error!("Failed to open device registry key"));
    }
    Ok(Self(key))
  }
  pub fn from_raw(key: HKEY) -> Self {
    Self(key)
  }
  pub fn as_raw(&self) -> HKEY {
    self.0
  }
  pub fn close(self) {
    drop(self)
  }
}

impl Drop for RegKey {
  fn drop(&mut self) {
    let key = std::mem::replace(&mut self.0, std::ptr::null_mut());
    unsafe { RegCloseKey(key) };
  }
}

/**
 * Validates and/or sanitizes string value read from registry.
 *
 * @param Buf           On input, it contains a pointer to pointer where the data is stored. The data must be allocated
 *                      using HeapAlloc(ModuleHeap, 0). On output, it contains a pointer to pointer where the sanitized
 *                      data is stored. It must be released with HeapFree(ModuleHeap, 0, *Buf) after use.
 *
 * @param Len           Length of data string in wide characters.
 *
 * @param ValueType     Type of data. Must be either REG_SZ or REG_EXPAND_SZ. REG_MULTI_SZ is treated like REG_SZ; only
 *                      the first string of a multi-string is to be used.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
pub fn registry_get_string(
  value: Box<[u8]>,
  value_type: RegistryValueType,
) -> std::io::Result<WideCString> {
  if value.len() & 1 != 0 {
    return ioeresult!(InvalidData, "Registry contained invalid utf16 string");
  }
  let value: Vec<u16> = value
    .chunks_exact(2)
    .map(|chunk| u16::from_ne_bytes(chunk.try_into().unwrap()))
    .collect();
  let value = WideCString::from(value);

  if value_type != RegistryValueType::RegExpandSz {
    return Ok(value);
  }
  if value.is_empty() {
    return Ok(value);
  }
  let mut expanded = value.clone();
  loop {
    let result = unsafe {
      ExpandEnvironmentStringsW(value.as_ptr(), expanded.as_mut_ptr(), expanded.capacity())
    };
    if result == 0 {
      let printable = value.display();
      return Err(last_error!(
        "Failed to expand environment variables: {}",
        printable
      ));
    }
    if result > value.len_dword() {
      let amount = result - value.len_dword();
      expanded.reserve(amount);
      continue;
    }
    return Ok(expanded);
  }
}

/**
 * Reads string value from registry key.
 *
 * @param Key           Handle of the registry key to read from. Must be opened with read access.
 *
 * @param Name          Name of the value to read.
 *
 * @param Value         Pointer to string to retrieve registry value. If the value type is REG_EXPAND_SZ the value is
 *                      expanded using ExpandEnvironmentStrings(). If the value type is REG_MULTI_SZ, only the first
 *                      string from the multi-string is returned. The string must be released with
 *                      HeapFree(ModuleHeap, 0, Value) after use.
 *
 * @Log                 Set to TRUE to log all failures; FALSE to skip logging the innermost errors. Skipping innermost
 *                      errors reduces log clutter when we are using RegistryQueryString() from
 *                      RegistryQueryStringWait() and some errors are expected to occur.
 *
 * @return String with registry value on success; If the function fails, the return value is zero. To get extended error
 *         information, call GetLastError.
 */
pub fn registry_query_string(
  key: &RegKey,
  name: impl AsRef<WideCStr>,
  log: bool,
) -> std::io::Result<WideCString> {
  let name = name.as_ref();
  let mut value_type = 0;
  let size = csizeof!(WCHAR; DWORD) * 256;
  let value = registry_query(key, name, &mut value_type, size, log)?;
  match value_type {
    REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ => {
      return registry_get_string(value, value_type.try_into().unwrap());
    }
    _ => {
      let reg_path = logger_get_registry_key_path(key);
      return Err(error!(
        ERROR_INVALID_DATATYPE,
        "Registry value {}\\{} is not a string (type: {})",
        reg_path.as_ref().display(),
        name.display(),
        value_type
      ));
    }
  }
}

/**
 * Reads a 32-bit DWORD value from registry key.
 *
 * @param Key           Handle of the registry key to read from. Must be opened with read access.
 *
 * @param Name          Name of the value to read.
 *
 * @param Value         Pointer to DWORD to retrieve registry value.
 *
 * @Log                 Set to TRUE to log all failures; FALSE to skip logging the innermost errors. Skipping innermost
 *                      errors reduces log clutter when we are using RegistryQueryDWORD() from
 *                      RegistryQueryDWORDWait() and some errors are expected to occur.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
pub fn registry_query_dword(
  key: &RegKey,
  name: impl AsRef<WideCStr>,
  log: bool,
) -> std::io::Result<DWORD> {
  let mut value_type = REG_DWORD;
  let mut size = csizeof!(DWORD; usize);
  let mut value: DWORD = 0;
  let name = name.as_ref();
  let name_ptr = name.as_ptr();
  let last_error = unsafe {
    RegQueryValueExW(
      key.as_raw(),
      name_ptr,
      std::ptr::null_mut(),
      value_type.get_mut_ptr(),
      value.get_mut_ptr() as *mut _,
      size.get_mut_ptr() as *mut _,
    )
  };
  if last_error != ERROR_SUCCESS as i32 {
    let err = std::io::Error::from_raw_os_error(last_error);
    if log {
      let reg_path = logger_get_registry_key_path(key);
      return Err(error!(
        err,
        "Failed to query registry value {}\\{}",
        reg_path.as_ref().display(),
        name.display()
      ));
    }
    return Err(err);
  }
  if value_type != REG_DWORD {
    let reg_path = logger_get_registry_key_path(key);
    return Err(error!(
      ERROR_INVALID_DATA,
      "Value {}\\{} is not a DWORD (type: {})",
      reg_path.as_ref().display(),
      name.display(),
      value_type
    ));
  }
  if size != csizeof!(DWORD) {
    let reg_path = logger_get_registry_key_path(key);
    return Err(error!(
      ERROR_INVALID_DATA,
      "Value {}\\{} size is not 4 bytes (size: {})",
      reg_path.as_ref().display(),
      name.display(),
      size
    ));
  }
  Ok(value)
}

fn registry_query(
  key: &RegKey,
  name: &WideCStr,
  value_type: &mut DWORD,
  mut buf_len: DWORD,
  log: bool,
) -> std::io::Result<Box<[u8]>> {
  let name_ptr = name.as_ptr();
  let mut p = vec![0 as BYTE; buf_len as usize];
  loop {
    let old_buf_len = buf_len;
    let last_error = unsafe {
      RegQueryValueExW(
        key.0,
        name_ptr,
        std::ptr::null_mut(),
        value_type.get_mut_ptr(),
        p.as_mut_ptr(),
        buf_len.get_mut_ptr(),
      )
    };
    if last_error == ERROR_SUCCESS as i32 {
      p.resize(buf_len as usize, 0);
      return Ok(p.into_boxed_slice());
    }
    if last_error as u32 != ERROR_MORE_DATA {
      let err = std::io::Error::from_raw_os_error(last_error);
      if log {
        let reg_path = logger_get_registry_key_path(key);
        return Err(error!(
          err,
          "Failed to query registry value {}\\{}",
          reg_path.as_ref().display(),
          name.display()
        ));
      }
      return Err(err);
    }
    p.extend(std::iter::repeat(' ' as u8).take((buf_len - old_buf_len) as usize));
  }
}
