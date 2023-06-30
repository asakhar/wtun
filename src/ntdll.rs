use std::ffi::CStr;

use winapi::shared::{
  minwindef::{DWORD, PULONG, UCHAR, ULONG, USHORT},
  ntdef::{HANDLE, NTSTATUS, PVOID, WCHAR},
};

use crate::registry::MAX_REG_PATH;

pub const SystemModuleInformation: i32 = 11;

#[repr(C)]
pub struct RTL_PROCESS_MODULE_INFORMATION {
  pub Section: HANDLE,
  pub MappedBase: PVOID,
  pub ImageBase: PVOID,
  pub ImageSize: ULONG,
  pub Flags: ULONG,
  pub LoadOrderIndex: USHORT,
  pub InitOrderIndex: USHORT,
  pub LoadCount: USHORT,
  pub OffsetToFileName: USHORT,
  pub FullPathName: [UCHAR; 256],
}

impl RTL_PROCESS_MODULE_INFORMATION {
  pub fn filename(&self) -> Option<&CStr> {
    unsafe { CStr::from_bytes_until_nul(&self.FullPathName[self.OffsetToFileName as usize..]) }.ok()
  }
  pub fn fullpath(&self) -> Option<&CStr> {
    unsafe { CStr::from_bytes_until_nul(&self.FullPathName) }.ok()
  }
}

pub type PRTL_PROCESS_MODULE_INFORMATION = *mut RTL_PROCESS_MODULE_INFORMATION;

#[repr(C)]
pub struct RTL_PROCESS_MODULES {
  NumberOfModules: ULONG,
  Modules: [RTL_PROCESS_MODULE_INFORMATION; 1],
}

impl RTL_PROCESS_MODULES {
  pub fn number(&self) -> ULONG {
    self.NumberOfModules
  }
  pub unsafe fn get_mut(&mut self, idx: ULONG) -> &mut RTL_PROCESS_MODULE_INFORMATION {
    &mut *self.Modules.as_mut_ptr().add(idx as usize)
  }
}

pub type PRTL_PROCESS_MODULES = *mut RTL_PROCESS_MODULES;
#[repr(C)]
pub struct KEY_NAME_INFORMATION {
  pub NameLength: ULONG,
  pub Name: [WCHAR; MAX_REG_PATH],
}

impl KEY_NAME_INFORMATION {
  pub const OFFSETOF_NAME: usize = std::mem::size_of::<ULONG>();
}
pub type PKEY_NAME_INFORMATION = *mut KEY_NAME_INFORMATION;

pub const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC0000004u32 as NTSTATUS;

extern "C" {
  /* We can't use RtlGetVersion, because appcompat's aclayers.dll shims it to report Vista
   * when run from legacy contexts. So, we instead use the undocumented RtlGetNtVersionNumbers.
   *
   * Another way would be reading from the PEB directly:
   *   ((DWORD *)NtCurrentTeb()->ProcessEnvironmentBlock)[sizeof(VOID *) == 8 ? 70 : 41]
   * Or just read from KUSER_SHARED_DATA the same way on 32-bit and 64-bit:
   *    *(DWORD *)0x7FFE026C
   */
  pub fn RtlGetNtVersionNumbers(
    /*_Out_*/ MajorVersion: *mut DWORD,
    /*_Out_*/ MinorVersion: *mut DWORD,
    /*_Out_*/ BuildNumber: *mut DWORD,
  );
  pub fn NtQueryKey(
    KeyHandle: HANDLE,
    KeyInformationClass: i32,
    /*_Out_bytecap_post_bytecount_(Length, *ResultLength)*/ KeyInformation: PVOID,
    Length: ULONG,
    /*_Out_*/ ResultLength: PULONG,
  ) -> DWORD;
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NtVersionNumbers {
  MajorVersion: DWORD,
  MinorVersion: DWORD,
  BuildNumber: DWORD,
}

pub fn rtl_get_nt_version_numbers() -> NtVersionNumbers {
  let mut version = NtVersionNumbers {
    MajorVersion: 0,
    MinorVersion: 0,
    BuildNumber: 0,
  };
  unsafe {
    RtlGetNtVersionNumbers(
      &mut version.MajorVersion as *mut DWORD,
      &mut version.MinorVersion as *mut DWORD,
      &mut version.BuildNumber as *mut DWORD,
    )
  };
  version
}
