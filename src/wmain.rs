use cutils::{csizeof, cstr, inspection::GetPtrExt, unsafe_defer, widecstr};
use winapi::{
  shared::{
    minwindef::{BOOL, DWORD, FALSE, TRUE, USHORT},
    ntdef::HANDLE,
    sddl::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
  },
  um::{
    handleapi::CloseHandle,
    libloaderapi::{GetModuleHandleW, GetProcAddress},
    minwinbase::SECURITY_ATTRIBUTES,
    processthreadsapi::{GetCurrentProcess, OpenProcessToken},
    securitybaseapi::{CreateWellKnownSid, EqualSid, GetTokenInformation},
    winefs::MAX_SID_SIZE,
    winnt::{TokenUser, WinLocalSystemSid, IMAGE_FILE_MACHINE_AMD64, TOKEN_QUERY, TOKEN_USER},
    wow64apiset::IsWow64Process,
  },
};

use crate::{
  adapter_win7::cleanup_lagacy_devices, logger::last_error, namespace::namespace_init,
  ntdll::RtlGetNtVersionNumbers,
};

pub struct SystemParams {
  pub security_attributes: SECURITY_ATTRIBUTES,
  pub is_local_system: bool,
  pub native_machine: USHORT,
  pub is_windows7: bool,
  pub is_windows10: bool,
}

impl std::fmt::Debug for SystemParams {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    struct SecAttrs<'a>(&'a SECURITY_ATTRIBUTES);
    impl<'a> std::fmt::Debug for SecAttrs<'a> {
      fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityAttributes")
          .field("bInheritHandle", &self.0.bInheritHandle)
          .field("lpSecurityDescriptor", &self.0.lpSecurityDescriptor)
          .field("nLength", &self.0.nLength)
          .finish()
      }
    }
    f.debug_struct("SystemParams")
      .field("SecurityAttributes", &SecAttrs(&self.security_attributes))
      .field("IsLocalSystem", &self.is_local_system)
      .field("NativeMachine", &self.native_machine)
      .field("IsWindows7", &self.is_windows7)
      .field("IsWindows10", &self.is_windows10)
      .finish()
  }
}
unsafe impl Sync for SystemParams {}
pub unsafe fn get_system_params<'a>() -> &'a mut SystemParams {
  static mut SYSTEM_PARAMS: std::cell::UnsafeCell<SystemParams> =
    std::cell::UnsafeCell::new(SystemParams {
      security_attributes: SECURITY_ATTRIBUTES {
        nLength: csizeof!(SECURITY_ATTRIBUTES),
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 0,
      },
      is_local_system: false,
      native_machine: 0,
      is_windows7: false,
      is_windows10: true,
    });
  static mut INIT: std::sync::OnceLock<&'static std::cell::UnsafeCell<SystemParams>> =
    std::sync::OnceLock::new();
  &mut *INIT
    .get_or_init(|| {
      let params = &mut *SYSTEM_PARAMS.get();
      let (security_attributes, is_local_system) = initialize_security_objects().unwrap();
      let (is_windows7, is_windows10, native_machine) = env_init();
      unsafe {
        namespace_init();
      }
      cleanup_lagacy_devices();
      *params = SystemParams {
        security_attributes,
        is_local_system,
        native_machine,
        is_windows7,
        is_windows10,
      };
      &SYSTEM_PARAMS
    })
    .get()
}
fn initialize_security_objects() -> std::io::Result<(SECURITY_ATTRIBUTES, bool)> {
  let mut security_attributes = SECURITY_ATTRIBUTES {
    nLength: csizeof!(SECURITY_ATTRIBUTES),
    lpSecurityDescriptor: std::ptr::null_mut(),
    bInheritHandle: 0,
  };
  let mut local_system_sid = [0u8; MAX_SID_SIZE];
  let mut required_bytes: DWORD = csizeof!(=local_system_sid);
  let mut current_process_token: HANDLE = std::ptr::null_mut();
  #[repr(C)]
  struct TokenUserStruct {
    maybe_local_system: TOKEN_USER,
    large_enough_for_local_system: [u8; MAX_SID_SIZE],
  }
  let mut token_user_buffer: TokenUserStruct = unsafe { std::mem::zeroed() };
  if unsafe {
    CreateWellKnownSid(
      WinLocalSystemSid,
      std::ptr::null_mut(),
      local_system_sid.as_mut_ptr().cast(),
      required_bytes.get_mut_ptr(),
    )
  } == FALSE
  {
    return Err(last_error!("Failed to create local system sid"));
  }
  if unsafe {
    OpenProcessToken(
      GetCurrentProcess(),
      TOKEN_QUERY,
      current_process_token.get_mut_ptr(),
    )
  } == FALSE
  {
    return Err(last_error!("Failed to open process token"));
  }
  unsafe_defer! { cleanup_process_token <-
    CloseHandle(current_process_token);
  };
  if unsafe {
    GetTokenInformation(
      current_process_token,
      TokenUser,
      token_user_buffer.get_mut_ptr().cast(),
      csizeof!(TokenUserStruct),
      required_bytes.get_mut_ptr(),
    )
  } == FALSE
  {
    return Err(last_error!("Failed to get process information"));
  }

  let is_local_system = unsafe {
    EqualSid(
      token_user_buffer.maybe_local_system.User.Sid,
      local_system_sid.as_mut_ptr().cast(),
    )
  } == TRUE;
  let string_sec_desc = if is_local_system {
    widecstr!("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)")
  } else {
    widecstr!("O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)")
  };
  if unsafe {
    ConvertStringSecurityDescriptorToSecurityDescriptorW(
      string_sec_desc.as_ptr(),
      SDDL_REVISION_1 as _,
      security_attributes.lpSecurityDescriptor.get_mut_ptr(),
      std::ptr::null_mut(),
    )
  } == FALSE
  {
    return Err(last_error!(
      "Failed to convert string security descriptor to security descriptor"
    ));
  }
  cleanup_process_token.run();
  Ok((security_attributes, is_local_system))
}
fn env_init() -> (bool, bool, USHORT) {
  let mut major_version = 0;
  let mut minor_version = 0;
  unsafe {
    RtlGetNtVersionNumbers(
      major_version.get_mut_ptr(),
      minor_version.get_mut_ptr(),
      std::ptr::null_mut(),
    )
  };
  #[cfg(feature = "windows7")]
  let is_windows7 = MajorVersion == 6 && MinorVersion == 1;
  #[cfg(not(feature = "windows7"))]
  let is_windows7 = false;
  #[cfg(feature = "windows10")]
  let is_windows10 = true;
  #[cfg(not(feature = "windows10"))]
  let is_windows10 = MajorVersion > 10;
  let mut native_machine = IMAGE_FILE_PROCESS;
  #[cfg(any(target_arch = "x86", target_arch = "arm", target_arch = "x86_64"))]
  {
    type IsWow64Process2Func = unsafe extern "system" fn(
      Process: HANDLE,
      ProcessMachine: *mut USHORT,
      NativeMachine: *mut USHORT,
    ) -> winapi::shared::minwindef::BOOL;
    let mut process_machine: USHORT = 0;
    let kernel32 = unsafe { GetModuleHandleW(widecstr!("kernel32.dll").as_ptr()) };
    let get_native_machine = || {
      let mut is_wow64: BOOL = FALSE;
      let cond = unsafe { IsWow64Process(GetCurrentProcess(), is_wow64.get_mut_ptr()) } == TRUE
        && is_wow64 == TRUE;
      return if cond {
        IMAGE_FILE_MACHINE_AMD64
      } else {
        IMAGE_FILE_PROCESS
      };
    };
    if kernel32.is_null() {
      return (is_windows7, is_windows10, get_native_machine());
    }
    let is_wow64_process2 =
      unsafe { GetProcAddress(kernel32, cstr!("IsWow64Process2").as_ptr().cast()) };
    if is_wow64_process2.is_null() {
      return (is_windows7, is_windows10, get_native_machine());
    }
    let is_wow64_process2: IsWow64Process2Func = unsafe { std::mem::transmute(is_wow64_process2) };
    if unsafe {
      is_wow64_process2(
        GetCurrentProcess(),
        process_machine.get_mut_ptr(),
        native_machine.get_mut_ptr(),
      )
    } == FALSE
    {
      return (is_windows7, is_windows10, get_native_machine());
    }
  }
  (is_windows7, is_windows10, native_machine)
}

#[cfg(target_arch = "x86")]
pub const IMAGE_FILE_PROCESS: USHORT = winapi::um::winnt::IMAGE_FILE_MACHINE_I386;
#[cfg(target_arch = "x86_64")]
pub const IMAGE_FILE_PROCESS: USHORT = winapi::um::winnt::IMAGE_FILE_MACHINE_AMD64;
#[cfg(target_arch = "arm")]
pub const IMAGE_FILE_PROCESS: USHORT = winapi::um::winnt::IMAGE_FILE_MACHINE_ARMNT;
#[cfg(target_arch = "aarch64")]
pub const IMAGE_FILE_PROCESS: USHORT = winapi::um::winnt::IMAGE_FILE_MACHINE_ARM64;
#[cfg(not(any(
  target_arch = "x86",
  target_arch = "x86_64",
  target_arch = "arm",
  target_arch = "aarch64"
)))]
compile_error!("Unsupported architecture");
