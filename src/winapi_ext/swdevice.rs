use winapi::{
  shared::{
    guiddef::GUID,
    minwindef::ULONG,
    ntdef::{HRESULT, PCWSTR, PCZZWSTR, PVOID},
  },
  um::winnt::SECURITY_DESCRIPTOR,
};

extern "system" {
  pub fn SwDeviceClose(hSwDevice: HSWDEVICE);
}
extern "system" {
  pub fn SwDeviceCreate(
    pszEnumeratorName: PCWSTR,
    pszParentDeviceInstance: PCWSTR,
    pCreateInfo: *const SW_DEVICE_CREATE_INFO,
    cPropertyCount: ULONG,
    pProperties: *const winapi::shared::devpropdef::DEVPROPERTY,
    pCallback: SW_DEVICE_CREATE_CALLBACK,
    pContext: PVOID,
    phSwDevice: PHSWDEVICE,
  ) -> HRESULT;
}
pub const None: SW_DEVICE_CAPABILITIES = 0;
pub const Removable: SW_DEVICE_CAPABILITIES = 1;
pub const SilentInstall: SW_DEVICE_CAPABILITIES = 2;
pub const NoDisplayInUI: SW_DEVICE_CAPABILITIES = 4;
pub const DriverRequired: SW_DEVICE_CAPABILITIES = 8;

pub type SW_DEVICE_CAPABILITIES = ::std::ffi::c_uint;
pub type PSW_DEVICE_CAPABILITIES = *mut SW_DEVICE_CAPABILITIES;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct HSWDEVICE__ {
  pub unused: ::std::os::raw::c_int,
}

pub type HSWDEVICE = *mut HSWDEVICE__;
pub type PHSWDEVICE = *mut HSWDEVICE;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SW_DEVICE_CREATE_INFO {
  pub cbSize: ULONG,
  pub pszInstanceId: PCWSTR,
  pub pszzHardwareIds: PCZZWSTR,
  pub pszzCompatibleIds: PCZZWSTR,
  pub pContainerId: *const GUID,
  pub CapabilityFlags: ULONG,
  pub pszDeviceDescription: PCWSTR,
  pub pszDeviceLocation: PCWSTR,
  pub pSecurityDescriptor: *const SECURITY_DESCRIPTOR,
}

pub type PSW_DEVICE_CREATE_INFO = *mut SW_DEVICE_CREATE_INFO;

pub type SW_DEVICE_CREATE_CALLBACK = ::std::option::Option<
  unsafe extern "system" fn(
    hSwDevice: HSWDEVICE,
    CreateResult: HRESULT,
    pContext: PVOID,
    pszDeviceInstanceId: PCWSTR,
  ),
>;
