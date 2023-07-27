use winapi::{
  shared::{
    guiddef::GUID,
    minwindef::ULONG,
    ntdef::{HRESULT, PCWSTR, PCZZWSTR, PVOID},
  },
  um::winnt::SECURITY_DESCRIPTOR,
};

extern "system" {
  pub(crate) fn SwDeviceClose(hSwDevice: HSWDEVICE);
  pub(crate) fn SwDeviceCreate(
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
pub(crate) const SilentInstall: SW_DEVICE_CAPABILITIES = 2;
pub(crate) const DriverRequired: SW_DEVICE_CAPABILITIES = 8;

pub(crate) type SW_DEVICE_CAPABILITIES = ::std::ffi::c_uint;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub(crate) struct HSWDEVICE__ {
  pub(crate) unused: ::std::os::raw::c_int,
}

pub(crate) type HSWDEVICE = *mut HSWDEVICE__;
pub(crate) type PHSWDEVICE = *mut HSWDEVICE;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub(crate) struct SW_DEVICE_CREATE_INFO {
  pub(crate) cbSize: ULONG,
  pub(crate) pszInstanceId: PCWSTR,
  pub(crate) pszzHardwareIds: PCZZWSTR,
  pub(crate) pszzCompatibleIds: PCZZWSTR,
  pub(crate) pContainerId: *const GUID,
  pub(crate) CapabilityFlags: ULONG,
  pub(crate) pszDeviceDescription: PCWSTR,
  pub(crate) pszDeviceLocation: PCWSTR,
  pub(crate) pSecurityDescriptor: *const SECURITY_DESCRIPTOR,
}

pub(crate) type SW_DEVICE_CREATE_CALLBACK = ::std::option::Option<
  unsafe extern "system" fn(
    hSwDevice: HSWDEVICE,
    CreateResult: HRESULT,
    pContext: PVOID,
    pszDeviceInstanceId: PCWSTR,
  ),
>;
