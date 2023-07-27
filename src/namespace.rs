use std::cell::UnsafeCell;

use cutils::{inspection::GetPtrExt, strings::WideCStr, unsafe_defer, widecstr, errors::get_last_error_code, csizeof};
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
  logger::{error, last_error},
  wmain::get_system_params,
};

pub struct SystemNamedMutexLock(HANDLE);

impl SystemNamedMutexLock {
  pub fn take_driver_installation_mutex() -> std::io::Result<Self> {
    Self::take(widecstr!(r"Wintun\Wintun-Driver-Installation-Mutex"))
  }
  pub fn take_device_installation_mutex() -> std::io::Result<Self> {
    Self::take(widecstr!(r"Wintun\Wintun-Device-Installation-Mutex"))
  }
  pub fn take(name: impl AsRef<WideCStr>) -> std::io::Result<Self> {
    namespace_runtime_init()?;
    let name = name.as_ref();
    let system_params = unsafe { get_system_params() };
    let mutex = unsafe {
      CreateMutexW(
        system_params.security_attributes.get_mut_ptr(),
        FALSE,
        name.as_ptr(),
      )
    };
    if mutex.is_null() {
      return Err(last_error!("Failed to create {} mutex", name.display()));
    }
    let result = unsafe { WaitForSingleObject(mutex, INFINITE) };
    if !matches!(result, WAIT_OBJECT_0 | WAIT_ABANDONED) {
      unsafe { CloseHandle(mutex) };
      return Err(last_error!("Failed to get mutex (status: 0x{:x})", result));
    }
    Ok(SystemNamedMutexLock(mutex))
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

pub unsafe fn namespace_init() {
  INITIALIZING.init();
}

pub unsafe fn namespace_done() {
  let section = unsafe { INITIALIZING.enter() };
  if !unsafe { PRIVATE_NAMESPACE.is_null() } {
    ClosePrivateNamespace(PRIVATE_NAMESPACE, 0);
    DeleteBoundaryDescriptor(BOUNDARY_DESCRIPTOR);
    PRIVATE_NAMESPACE = std::ptr::null_mut();
    BOUNDARY_DESCRIPTOR = std::ptr::null_mut();
  }
  section.leave();
  unsafe { INITIALIZING.delete() };
}

struct SystemCriticalSection(UnsafeCell<CRITICAL_SECTION>);

impl SystemCriticalSection {
  const fn new() -> Self {
    // const impl of:
    //  let section: CRITICAL_SECTION = unsafe { std::mem::zeroed() };
    let section_bytes = [0u8; csizeof!(CRITICAL_SECTION)];
    let section: CRITICAL_SECTION = unsafe { std::mem::transmute(section_bytes) };
    let section = UnsafeCell::new(section);
    SystemCriticalSection(section)
  }
  unsafe fn init(&self) {
    let section_ptr = self.0.get();
    InitializeCriticalSection(section_ptr);
  }
  unsafe fn enter(&self) -> SystemCriticalSectionLock {
    let section = self.0.get();
    EnterCriticalSection(section);
    SystemCriticalSectionLock(section)
  }
  unsafe fn delete(&self) {
    DeleteCriticalSection(self.0.get())
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

static INITIALIZING: SystemCriticalSection = SystemCriticalSection::new();

static mut PRIVATE_NAMESPACE: HANDLE = std::ptr::null_mut();
static mut BOUNDARY_DESCRIPTOR: HANDLE = std::ptr::null_mut();

fn namespace_runtime_init() -> std::io::Result<()> {
  let section = unsafe { INITIALIZING.enter() };
  if !unsafe { PRIVATE_NAMESPACE.is_null() } {
    return Ok(());
  }

  let mut sid = [0 as BYTE; MAX_SID_SIZE];
  let mut sid_size = csizeof!(=sid; DWORD);
  let system_params = unsafe { get_system_params() };
  let result = unsafe {
    CreateWellKnownSid(
      if system_params.is_local_system {
        WinLocalSystemSid
      } else {
        WinBuiltinAdministratorsSid
      },
      std::ptr::null_mut(),
      sid.as_mut_ptr() as *mut _,
      sid_size.get_mut_ptr(),
    )
  };
  if result == FALSE {
    return Err(last_error!("Failed to create SID"));
  }
  unsafe { BOUNDARY_DESCRIPTOR = CreateBoundaryDescriptorW(widecstr!("Wintun").as_ptr(), 0) };
  if unsafe { BOUNDARY_DESCRIPTOR.is_null() } {
    return Err(last_error!("Failed to create boundary descriptor"));
  }
  unsafe_defer! { cleanup_boundary_descriptor <-
    DeleteBoundaryDescriptor(BOUNDARY_DESCRIPTOR);
  };
  let result = unsafe {
    AddSIDToBoundaryDescriptor(BOUNDARY_DESCRIPTOR.get_mut_ptr(), sid.as_mut_ptr() as *mut _)
  };
  if result == FALSE {
    return Err(last_error!("Failed to add SID to boundary descriptor"));
  }
  let system_params = unsafe { get_system_params() };
  loop {
    unsafe {
      PRIVATE_NAMESPACE = CreatePrivateNamespaceW(
        system_params.security_attributes.get_mut_ptr(),
        BOUNDARY_DESCRIPTOR,
        widecstr!("Wintun").as_ptr(),
      )
    };
    if !unsafe { PRIVATE_NAMESPACE.is_null() } {
      break;
    }
    let last_error = get_last_error_code();
    if last_error != ERROR_ALREADY_EXISTS {
      return Err(error!(last_error, "Failed to create private namespace"));
    }
    unsafe {
      PRIVATE_NAMESPACE = OpenPrivateNamespaceW(BOUNDARY_DESCRIPTOR, widecstr!("Wintun").as_ptr())
    };
    if !unsafe { PRIVATE_NAMESPACE.is_null() } {
      break;
    }
    let last_error = get_last_error_code();
    if last_error == ERROR_PATH_NOT_FOUND {
      continue;
    }
    return Err(error!(last_error, "Failed to open private namespace"));
  }
  cleanup_boundary_descriptor.forget();
  section.leave();
  Ok(())
}
