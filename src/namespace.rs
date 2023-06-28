use std::cell::UnsafeCell;

use cutils::{unsafe_defer, inspection::GetPtrExt, strings::WideCStr, widecstr, Win32Result};
use get_last_error::Win32Error;
use lazy_static::lazy_static;
use winapi::{
  shared::{
    minwindef::{BYTE, DWORD, FALSE},
    ntdef::HANDLE,
    winerror::{ERROR_ALREADY_EXISTS, ERROR_PATH_NOT_FOUND},
  },
  um::{
    handleapi::CloseHandle,
    minwinbase::CRITICAL_SECTION,
    namespaceapi::{
      AddSIDToBoundaryDescriptor, ClosePrivateNamespace, CreateBoundaryDescriptorW,
      CreatePrivateNamespaceW, DeleteBoundaryDescriptor, OpenPrivateNamespaceW,
    },
    securitybaseapi::CreateWellKnownSid,
    synchapi::{
      CreateMutexW, DeleteCriticalSection, EnterCriticalSection, InitializeCriticalSection,
      LeaveCriticalSection, ReleaseMutex, WaitForSingleObject,
    },
    winbase::{INFINITE, WAIT_ABANDONED, WAIT_OBJECT_0},
    winefs::MAX_SID_SIZE,
    winnt::{WinBuiltinAdministratorsSid, WinLocalSystemSid},
  },
};

use crate::{
  logger::{last_error, error},
  wmain::{IsLocalSystem, SecurityAttributes},
};

pub struct SystemNamedMutexLock(HANDLE);

impl SystemNamedMutexLock {
  pub fn take_driver_installation_mutex() -> Win32Result<Self> {
    Self::take(widecstr!(r"Wintun\Wintun-Driver-Installation-Mutex"))
  }
  pub fn take_device_installation_mutex() -> Win32Result<Self> {
    Self::take(widecstr!(r"Wintun\Wintun-Device-Installation-Mutex"))
  }
  pub fn take(name: impl AsRef<WideCStr>) -> Win32Result<Self> {
    NamespaceRuntimeInit()?;
    let name = name.as_ref();
    let Mutex = unsafe { CreateMutexW(SecurityAttributes.get_mut_ptr(), FALSE, name.as_ptr()) };
    if Mutex.is_null() {
      return Err(last_error!("Failed to create {} mutex", name.display()));
    }
    let result = unsafe { WaitForSingleObject(Mutex, INFINITE) };
    if !matches!(result, WAIT_OBJECT_0 | WAIT_ABANDONED) {
      unsafe { CloseHandle(Mutex) };
      return Err(last_error!("Failed to get mutex (status: 0x{:x})", result));
    }
    Ok(SystemNamedMutexLock(Mutex))
  }
  pub fn release(self) {
    drop(self)
  }
}

impl Drop for SystemNamedMutexLock {
  fn drop(&mut self) {
    unsafe {
      ReleaseMutex(self.0);
      CloseHandle(self.0)
    };
  }
}

pub unsafe fn NamespaceInit() {
  Initializing.init();
}

pub unsafe fn NamespaceDone() {
  let section = unsafe { Initializing.enter() };
  if !unsafe { PrivateNamespace.is_null() } {
    ClosePrivateNamespace(PrivateNamespace, 0);
    DeleteBoundaryDescriptor(BoundaryDescriptor);
    PrivateNamespace = std::ptr::null_mut();
    BoundaryDescriptor = std::ptr::null_mut();
  }
  section.leave();
  unsafe { Initializing.delete() };
}

struct SystemCriticalSection(UnsafeCell<CRITICAL_SECTION>);

impl SystemCriticalSection {
  fn new() -> Self {
    let section: CRITICAL_SECTION = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    let section = UnsafeCell::new(section);
    SystemCriticalSection(section)
  }
  unsafe fn init(&self) {
    let section_ptr = self.0.get_mut() as *mut _;
    InitializeCriticalSection(section_ptr);
  }
  unsafe fn enter(&self) -> SystemCriticalSectionLock {
    let section = self.0.get();
    EnterCriticalSection(section);
    SystemCriticalSectionLock(section)
  }
  unsafe fn delete(&self) {
    DeleteCriticalSection(self.0.get_mut())
  }
}

unsafe impl Send for SystemCriticalSection {}
unsafe impl Sync for SystemCriticalSection {}

struct SystemCriticalSectionLock(*mut CRITICAL_SECTION);

impl SystemCriticalSectionLock {
  pub fn leave(self) {
    drop(self)
  }
}

impl Drop for SystemCriticalSectionLock {
  fn drop(&mut self) {
    unsafe { LeaveCriticalSection(self.0) }
  }
}

lazy_static! {
  static ref Initializing: SystemCriticalSection = SystemCriticalSection::new();
}

static mut PrivateNamespace: HANDLE = std::ptr::null_mut();
static mut BoundaryDescriptor: HANDLE = std::ptr::null_mut();

fn NamespaceRuntimeInit() -> Win32Result<()> {
  let section = unsafe { Initializing.enter() };
  if !unsafe { PrivateNamespace.is_null() } {
    return Ok(());
  }

  let mut Sid = [0 as BYTE; MAX_SID_SIZE];
  let mut SidSize = std::mem::size_of_val(&Sid) as DWORD;
  let result = unsafe {
    CreateWellKnownSid(
      if IsLocalSystem {
        WinLocalSystemSid
      } else {
        WinBuiltinAdministratorsSid
      },
      std::ptr::null_mut(),
      Sid.as_mut_ptr() as *mut _,
      SidSize.get_mut_ptr(),
    )
  };
  if result == FALSE {
    return Err(last_error!("Failed to create SID"));
  }
  unsafe { BoundaryDescriptor = CreateBoundaryDescriptorW(widecstr!("Wintun").as_ptr(), 0) };
  if unsafe { BoundaryDescriptor.is_null() } {
    return Err(last_error!("Failed to create boundary descriptor"));
  }
  unsafe_defer! { cleanupBoundaryDescriptor <-
    DeleteBoundaryDescriptor(BoundaryDescriptor);
  };
  let result = unsafe {
    AddSIDToBoundaryDescriptor(BoundaryDescriptor.get_mut_ptr(), Sid.as_mut_ptr() as *mut _)
  };
  if result == FALSE {
    return Err(last_error!("Failed to add SID to boundary descriptor"));
  }
  loop {
    unsafe {
      PrivateNamespace = CreatePrivateNamespaceW(
        SecurityAttributes.get_mut_ptr(),
        BoundaryDescriptor,
        widecstr!("Wintun").as_ptr(),
      )
    };
    if !unsafe { PrivateNamespace.is_null() } {
      break;
    }
    let LastError = Win32Error::get_last_error();
    if LastError.code() != ERROR_ALREADY_EXISTS {
      return Err(error!(LastError, "Failed to create private namespace"));
    }
    unsafe {
      PrivateNamespace = OpenPrivateNamespaceW(BoundaryDescriptor, widecstr!("Wintun").as_ptr())
    };
    if !unsafe { PrivateNamespace.is_null() } {
      break;
    }
    let LastError = Win32Error::get_last_error();
    if LastError.code() == ERROR_PATH_NOT_FOUND {
      continue;
    }
    return Err(error!(LastError, "Failed to open private namespace"));
  }
  cleanupBoundaryDescriptor.forget();
  section.leave();
  Ok(())
}
