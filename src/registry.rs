use get_last_error::Win32Error;
use widestring::{U16CString, WideCStr, WideCString};
use winapi::{
  shared::{
    minwindef::{BYTE, DWORD, HKEY},
    ntdef::WCHAR,
    winerror::{ERROR_INVALID_DATA, ERROR_INVALID_DATATYPE, ERROR_MORE_DATA, ERROR_SUCCESS},
  },
  um::{
    handleapi::INVALID_HANDLE_VALUE,
    processenv::ExpandEnvironmentStringsW,
    setupapi::{SetupDiOpenDevRegKey, HDEVINFO, PSP_DEVINFO_DATA},
    winnt::{REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ},
    winreg::{RegCloseKey, RegQueryValueExW, REGSAM},
  },
};

use crate::{
  last_error,
  logger::LoggerGetRegistryKeyPath,
  utils::{set_last_error, GetPtrExt, Win32ErrorToResultExt, Win32Result},
};

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
    DeviceInfoSet: HDEVINFO,
    DeviceInfoData: PSP_DEVINFO_DATA,
    Scope: DWORD,
    HwProfile: DWORD,
    KeyType: DWORD,
    samDesired: REGSAM,
  ) -> Win32Result<Self> {
    let Key: HKEY = unsafe {
      SetupDiOpenDevRegKey(
        DeviceInfoSet,
        DeviceInfoData,
        Scope,
        HwProfile,
        KeyType,
        samDesired,
      )
    };
    if [INVALID_HANDLE_VALUE as HKEY, std::ptr::null_mut()].contains(&Key) {
      return Err(last_error!("Failed to open device registry key"));
    }
    Ok(Self(Key))
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
pub fn RegistryGetString(
  value: Box<[u8]>,
  value_type: RegistryValueType,
) -> Win32Result<WideCString> {
  if value.len() & 1 != 0 {
    return Err(Win32Error::new(ERROR_INVALID_DATA));
  }
  let (pref, _, suff): (_, &[WCHAR], _) = unsafe { value.align_to() };
  if !pref.is_empty() || !suff.is_empty() {
    return Err(Win32Error::new(ERROR_INVALID_DATA));
  }
  let value_len = value.len();
  let value_ptr = Box::<[u8]>::into_raw(value);
  let value_ptr = value_ptr as *mut WCHAR;
  let value_len = value_len / std::mem::size_of::<WCHAR>();
  let value = std::ptr::slice_from_raw_parts_mut(value_ptr, value_len);
  let mut value = unsafe { Box::from_raw(value) }.into_vec();
  let count = value.iter().take_while(|item| **item != 0).count();
  value.resize(count, 0);
  let value = WideCString::from_vec(value)
    .ok()
    .ok_or(Win32Error::new(ERROR_INVALID_DATA))?;

  if value_type != RegistryValueType::RegExpandSz {
    return Ok(value);
  }
  if value.is_empty() {
    return Ok(value);
  }
  let mut expanded = value.clone();
  loop {
    let Result = unsafe {
      ExpandEnvironmentStringsW(value.as_ptr(), expanded.as_mut_ptr(), expanded.len() as u32)
    };
    if Result == 0 {
      let printable = value.display();
      return Err(last_error!(
        "Failed to expand environment variables: {}",
        printable
      ));
    }
    if Result as usize > value.len() {
      let amount = Result as usize - value.len();
      let mut expanded_vec = expanded.into_vec();
      expanded_vec.extend(std::iter::repeat(' ' as WCHAR).take(amount));
      expanded = U16CString::from_vec(expanded_vec).unwrap();
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
pub fn RegistryQueryString(
  Key: &RegKey,
  Name: impl AsRef<WideCStr>,
  Log: bool,
) -> Win32Result<WideCString> {
  let Name = Name.as_ref();
  let mut ValueType = 0;
  let Size = std::mem::size_of::<WCHAR>() as DWORD * 256;
  let value = RegistryQuery(Key, Name, &mut ValueType, Size, Log)?;
  match ValueType {
    REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ => {
      return RegistryGetString(value, ValueType.try_into().unwrap());
    }
    _ => {
      let RegPath = LoggerGetRegistryKeyPath(Key);
      set_last_error(Win32Error::new(ERROR_INVALID_DATATYPE));
      return Err(last_error!(
        "Registry value {}\\{} is not a string (type: {})",
        RegPath.display(),
        Name.display(),
        ValueType
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
pub fn RegistryQueryDWORD(
  Key: &RegKey,
  Name: impl AsRef<WideCStr>,
  Log: bool,
) -> Win32Result<DWORD> {
  let mut ValueType = REG_DWORD;
  let mut Size = std::mem::size_of::<DWORD>();
  let mut Value: DWORD = 0;
  let Name = Name.as_ref();
  let NamePtr = Name.as_ptr();
  let LastError = unsafe {
    RegQueryValueExW(
      Key.as_raw(),
      NamePtr,
      std::ptr::null_mut(),
      ValueType.get_mut_ptr(),
      Value.get_mut_ptr() as *mut _,
      Size.get_mut_ptr() as *mut _,
    )
  };
  if LastError != ERROR_SUCCESS as i32 {
    set_last_error(Win32Error::new(LastError as u32));
    if Log {
      let RegPath = LoggerGetRegistryKeyPath(Key);
      return Err(last_error!(
        "Failed to query registry value {}\\{}",
        RegPath.display(),
        Name.display()
      ));
    }
    Win32Error::get_last_error().to_result()?;
    unreachable!();
  }
  if ValueType != REG_DWORD {
    let RegPath = LoggerGetRegistryKeyPath(Key);
    set_last_error(Win32Error::new(ERROR_INVALID_DATA));
    return Err(last_error!(
      "Value {}\\{} is not a DWORD (type: {})",
      RegPath.display(),
      Name.display(),
      ValueType
    ));
  }
  if Size != std::mem::size_of::<DWORD>() {
    let RegPath = LoggerGetRegistryKeyPath(Key);
    set_last_error(Win32Error::new(ERROR_INVALID_DATA));
    return Err(last_error!(
      "Value {}\\{} size is not 4 bytes (size: {})",
      RegPath.display(),
      Name.display(),
      Size
    ));
  }
  Ok(Value)
}

fn RegistryQuery(
  Key: &RegKey,
  Name: &WideCStr,
  ValueType: &mut DWORD,
  mut BufLen: DWORD,
  Log: bool,
) -> Win32Result<Box<[u8]>> {
  let NamePtr = Name.as_ptr();
  let mut p = vec![0 as BYTE; BufLen as usize];
  loop {
    let OldBufLen = BufLen;
    let LastError = unsafe {
      RegQueryValueExW(
        Key.0,
        NamePtr,
        std::ptr::null_mut(),
        ValueType.get_mut_ptr(),
        p.as_mut_ptr(),
        BufLen.get_mut_ptr(),
      )
    };
    if LastError == ERROR_SUCCESS as i32 {
      p.resize(BufLen as usize, 0);
      return Ok(p.into_boxed_slice());
    }
    if LastError as u32 != ERROR_MORE_DATA {
      set_last_error(Win32Error::new(LastError as u32));
      if Log {
        let RegPath = LoggerGetRegistryKeyPath(Key);
        return Err(last_error!(
          "Failed to query registry value {}\\{}",
          RegPath.display(),
          Name.display()
        ));
      }
      Win32Error::get_last_error().to_result()?;
      unreachable!();
    }
    p.extend(std::iter::repeat(' ' as u8).take((BufLen - OldBufLen) as usize));
  }
}
