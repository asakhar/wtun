use std::ffi::CStr;

use winapi::shared::{
  minwindef::{DWORD, PULONG, UCHAR, ULONG, USHORT},
  ntdef::{HANDLE, NTSTATUS, PVOID, WCHAR},
};

use crate::registry::MAX_REG_PATH;

pub const SYSTEM_MODULE_INFORMATION: i32 = 11;

#[repr(C)]
pub struct RtlProcessModuleInformation {
  pub section: HANDLE,
  pub mapped_base: PVOID,
  pub image_base: PVOID,
  pub image_size: ULONG,
  pub flags: ULONG,
  pub load_order_index: USHORT,
  pub init_order_index: USHORT,
  pub load_count: USHORT,
  pub offset_to_file_name: USHORT,
  pub full_path_name: [UCHAR; 256],
}

impl RtlProcessModuleInformation {
  pub fn filename(&self) -> Option<&CStr> {
    unsafe { CStr::from_bytes_until_nul(&self.full_path_name[self.offset_to_file_name as usize..]) }
      .ok()
  }
  pub fn fullpath(&self) -> Option<&CStr> {
    unsafe { CStr::from_bytes_until_nul(&self.full_path_name) }.ok()
  }
}
#[allow(dead_code)]
pub type PrtlProcessModuleInformation = *mut RtlProcessModuleInformation;

#[repr(C)]
pub struct RtlProcessModules {
  number_of_modules: ULONG,
  modules: [RtlProcessModuleInformation; 1],
}

impl RtlProcessModules {
  pub fn number(&self) -> ULONG {
    self.number_of_modules
  }
  pub unsafe fn get_mut(&mut self, idx: ULONG) -> &mut RtlProcessModuleInformation {
    &mut *self.modules.as_mut_ptr().add(idx as usize)
  }
}

#[allow(dead_code)]
pub type PrtlProcessModules = *mut RtlProcessModules;
#[repr(C)]
pub struct KeyNameInformation {
  pub name_length: ULONG,
  pub name: [WCHAR; MAX_REG_PATH],
}

impl KeyNameInformation {
  pub const OFFSETOF_NAME: usize = std::mem::size_of::<ULONG>();
}

#[allow(dead_code)]
pub type PkeyNameInformation = *mut KeyNameInformation;
#[allow(dead_code)]
pub const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC0000004u32 as NTSTATUS;

extern "system" {
  // We can't use RtlGetVersion, because appcompat's aclayers.dll shims it to report Vista
  // when run from legacy contexts. So, we instead use the undocumented RtlGetNtVersionNumbers.
  //
  // Another way would be reading from the PEB directly:
  //   ((DWORD *)NtCurrentTeb()->ProcessEnvironmentBlock)[sizeof(VOID *) == 8 ? 70 : 41]
  // Or just read from KUSER_SHARED_DATA the same way on 32-bit and 64-bit: *(DWORD *)0x7FFE026C
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
  major_version: DWORD,
  minor_version: DWORD,
  build_number: DWORD,
}

#[allow(dead_code)]
pub fn rtl_get_nt_version_numbers() -> NtVersionNumbers {
  let mut version = NtVersionNumbers {
    major_version: 0,
    minor_version: 0,
    build_number: 0,
  };
  unsafe {
    RtlGetNtVersionNumbers(
      &mut version.major_version as *mut DWORD,
      &mut version.minor_version as *mut DWORD,
      &mut version.build_number as *mut DWORD,
    )
  };
  version
}
