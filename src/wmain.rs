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
  adapter_win7::cleanup_lagacy_devices, logger::last_error, namespace::NamespaceInit,
  ntdll::RtlGetNtVersionNumbers,
};

pub struct SystemParams {
  pub SecurityAttributes: SECURITY_ATTRIBUTES,
  pub IsLocalSystem: bool,
  pub NativeMachine: USHORT,
  pub IsWindows7: bool,
  pub IsWindows10: bool,
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
      .field("SecurityAttributes", &SecAttrs(&self.SecurityAttributes))
      .field("IsLocalSystem", &self.IsLocalSystem)
      .field("NativeMachine", &self.NativeMachine)
      .field("IsWindows7", &self.IsWindows7)
      .field("IsWindows10", &self.IsWindows10)
      .finish()
  }
}
unsafe impl Sync for SystemParams {}
pub unsafe fn get_system_params<'a>() -> &'a mut SystemParams {
  static mut SYSTEM_PARAMS: std::cell::UnsafeCell<SystemParams> =
    std::cell::UnsafeCell::new(SystemParams {
      SecurityAttributes: SECURITY_ATTRIBUTES {
        nLength: csizeof!(SECURITY_ATTRIBUTES),
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 0,
      },
      IsLocalSystem: false,
      NativeMachine: 0,
      IsWindows7: false,
      IsWindows10: true,
    });
  static mut INIT: std::sync::OnceLock<&'static std::cell::UnsafeCell<SystemParams>> =
    std::sync::OnceLock::new();
  &mut *INIT
    .get_or_init(|| {
      let params = &mut *SYSTEM_PARAMS.get();
      let (SecurityAttributes, IsLocalSystem) = InitializeSecurityObjects().unwrap();
      let (IsWindows7, IsWindows10, NativeMachine) = EnvInit();
      unsafe {
        NamespaceInit();
      }
      cleanup_lagacy_devices();
      *params = SystemParams {
        SecurityAttributes,
        IsLocalSystem,
        NativeMachine,
        IsWindows7,
        IsWindows10,
      };
      &SYSTEM_PARAMS
    })
    .get()
}
fn InitializeSecurityObjects() -> std::io::Result<(SECURITY_ATTRIBUTES, bool)> {
  let mut SecurityAttributes = SECURITY_ATTRIBUTES {
    nLength: csizeof!(SECURITY_ATTRIBUTES),
    lpSecurityDescriptor: std::ptr::null_mut(),
    bInheritHandle: 0,
  };
  let mut LocalSystemSid = [0u8; MAX_SID_SIZE];
  let mut RequiredBytes: DWORD = csizeof!(=LocalSystemSid);
  let mut CurrentProcessToken: HANDLE = std::ptr::null_mut();
  #[repr(C)]
  struct TokenUserStruct {
    MaybeLocalSystem: TOKEN_USER,
    LargeEnoughForLocalSystem: [u8; MAX_SID_SIZE],
  }
  let mut TokenUserBuffer: TokenUserStruct = unsafe { std::mem::zeroed() };
  if unsafe {
    CreateWellKnownSid(
      WinLocalSystemSid,
      std::ptr::null_mut(),
      LocalSystemSid.as_mut_ptr().cast(),
      RequiredBytes.get_mut_ptr(),
    )
  } == FALSE
  {
    return Err(last_error!("Failed to create local system sid"));
  }
  if unsafe {
    OpenProcessToken(
      GetCurrentProcess(),
      TOKEN_QUERY,
      CurrentProcessToken.get_mut_ptr(),
    )
  } == FALSE
  {
    return Err(last_error!("Failed to open process token"));
  }
  unsafe_defer! { cleanupProcessToken <-
    CloseHandle(CurrentProcessToken);
  };
  if unsafe {
    GetTokenInformation(
      CurrentProcessToken,
      TokenUser,
      TokenUserBuffer.get_mut_ptr().cast(),
      csizeof!(TokenUserStruct),
      RequiredBytes.get_mut_ptr(),
    )
  } == FALSE
  {
    return Err(last_error!("Failed to get process information"));
  }

  let IsLocalSystem = unsafe {
    EqualSid(
      TokenUserBuffer.MaybeLocalSystem.User.Sid,
      LocalSystemSid.as_mut_ptr().cast(),
    )
  } == TRUE;
  let string_sec_desc = if IsLocalSystem {
    widecstr!("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)")
  } else {
    widecstr!("O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)")
  };
  if unsafe {
    ConvertStringSecurityDescriptorToSecurityDescriptorW(
      string_sec_desc.as_ptr(),
      SDDL_REVISION_1 as _,
      SecurityAttributes.lpSecurityDescriptor.get_mut_ptr(),
      std::ptr::null_mut(),
    )
  } == FALSE
  {
    return Err(last_error!(
      "Failed to convert string security descriptor to security descriptor"
    ));
  }
  cleanupProcessToken.run();
  Ok((SecurityAttributes, IsLocalSystem))
}
fn EnvInit() -> (bool, bool, USHORT) {
  let mut MajorVersion = 0;
  let mut MinorVersion = 0;
  unsafe {
    RtlGetNtVersionNumbers(
      MajorVersion.get_mut_ptr(),
      MinorVersion.get_mut_ptr(),
      std::ptr::null_mut(),
    )
  };
  #[cfg(feature = "windows7")]
  let IsWindows7 = MajorVersion == 6 && MinorVersion == 1;
  #[cfg(not(feature = "windows7"))]
  let IsWindows7 = false;
  #[cfg(feature = "windows10")]
  let IsWindows10 = true;
  #[cfg(not(feature = "windows10"))]
  let IsWindows10 = MajorVersion > 10;
  let mut NativeMachine = IMAGE_FILE_PROCESS;
  #[cfg(any(target_arch = "x86", target_arch = "arm", target_arch = "x86_64"))]
  {
    type IsWow64Process2Func = unsafe extern "system" fn(
      Process: HANDLE,
      ProcessMachine: *mut USHORT,
      NativeMachine: *mut USHORT,
    ) -> winapi::shared::minwindef::BOOL;
    let mut ProcessMachine: USHORT = 0;
    let kernel32 = unsafe { GetModuleHandleW(widecstr!("kernel32.dll").as_ptr()) };
    let get_native_machine = || {
      let mut IsWoW64: BOOL = FALSE;
      let cond = unsafe { IsWow64Process(GetCurrentProcess(), IsWoW64.get_mut_ptr()) } == TRUE
        && IsWoW64 == TRUE;
      return if cond {
        IMAGE_FILE_MACHINE_AMD64
      } else {
        IMAGE_FILE_PROCESS
      };
    };
    if kernel32.is_null() {
      return (IsWindows7, IsWindows10, get_native_machine());
    }
    let IsWow64Process2 =
      unsafe { GetProcAddress(kernel32, cstr!("IsWow64Process2").as_ptr().cast()) };
    if IsWow64Process2.is_null() {
      return (IsWindows7, IsWindows10, get_native_machine());
    }
    let IsWow64Process2: IsWow64Process2Func = unsafe { std::mem::transmute(IsWow64Process2) };
    if unsafe {
      IsWow64Process2(
        GetCurrentProcess(),
        ProcessMachine.get_mut_ptr(),
        NativeMachine.get_mut_ptr(),
      )
    } == FALSE
    {
      return (IsWindows7, IsWindows10, get_native_machine());
    }
  }
  (IsWindows7, IsWindows10, NativeMachine)
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
