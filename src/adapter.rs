use std::sync::atomic::AtomicBool;

use cutils::Win32Result;
use cutils::inspection::{InitZeroed, GetPtrExt};
use get_last_error::Win32Error;
use widestring::{widecstr, widestr, WideCStr, WideCString, WideStr};
use winapi::shared::cfg::DN_HAS_PROBLEM;
use winapi::shared::devguid::GUID_DEVCLASS_NET;
use winapi::shared::devpkey::{
  DEVPKEY_DeviceInterface_ClassGuid, DEVPKEY_DeviceInterface_Enabled, DEVPKEY_Device_InstanceId,
};
use winapi::shared::devpropdef::{
  DEVPROPCOMPKEY, DEVPROPERTY, DEVPROPGUID, DEVPROPID_FIRST_USABLE, DEVPROPKEY, DEVPROPTYPE,
  DEVPROP_BOOLEAN, DEVPROP_STORE_SYSTEM, DEVPROP_TRUE, DEVPROP_TYPE_BOOLEAN, DEVPROP_TYPE_GUID,
  DEVPROP_TYPE_STRING,
};
use winapi::shared::guiddef::GUID;
use winapi::shared::ifdef::NET_LUID;
use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::shared::minwindef::{FALSE, HKEY, ULONG};
use winapi::shared::netioapi::{ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToGuid};
use winapi::shared::ntdef::{HANDLE, LPCWSTR, PCWSTR};
use winapi::shared::winerror::{
  ERROR_BUFFER_OVERFLOW, ERROR_DEVICE_NOT_AVAILABLE, ERROR_DUP_NAME, ERROR_GEN_FAILURE,
  ERROR_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, FAILED, HRESULT, NO_ERROR, S_OK,
};
use winapi::um::cfgmgr32::{
  CM_Get_DevNode_Status, CM_Get_Device_IDW, CM_Get_Device_Interface_ListW,
  CM_Get_Device_Interface_List_SizeW, CM_Locate_DevNodeW, CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
  CM_LOCATE_DEVNODE_NORMAL, CONFIGRET, CR_SUCCESS, DEVINST, DEVINSTID_W, MAX_DEVICE_ID_LEN,
  MAX_GUID_STRING_LEN,
};
use winapi::um::combaseapi::{CLSIDFromString, CoCreateGuid, StringFromGUID2};
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ipexport::MAX_ADAPTER_NAME;
use winapi::um::setupapi::{
  SetupDiCallClassInstaller, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
  SetupDiGetClassDevsExW, SetupDiOpenDevRegKey, SetupDiSetClassInstallParamsW,
  SetupDiSetDevicePropertyW, DICS_DISABLE, DICS_ENABLE, DIF_PROPERTYCHANGE, DIF_REMOVE,
  DI_REMOVEDEVICE_GLOBAL, SP_CLASSINSTALL_HEADER, SP_PROPCHANGE_PARAMS, SP_REMOVEDEVICE_PARAMS,
};
use winapi::um::setupapi::{SetupDiGetDevicePropertyW, DICS_FLAG_GLOBAL};
use winapi::um::setupapi::{DIREG_DRV, HDEVINFO, SP_DEVINFO_DATA};
use winapi::um::synchapi::{CreateEventW, SetEvent, WaitForSingleObject};
use winapi::um::winbase::{WAIT_FAILED, WAIT_OBJECT_0};
use winapi::um::winnt::{
  FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE,
  KEY_QUERY_VALUE, PVOID, WCHAR,
};
use winapi::DEFINE_GUID;

use crate::driver::DriverInstall;
use crate::logger::LoggerGetRegistryKeyPath;
use crate::namespace::SystemNamedMutexLock;
use crate::nci::SetConnectionName;
use crate::registry::{RegKey, RegistryQueryDWORD, RegistryQueryString};
use crate::winapi_ext::devquery::{
  DevCloseObjectQuery, DevCreateObjectQuery, _DEV_OBJECT_TYPE_DevObjectTypeDeviceInterface,
  _DEV_QUERY_FLAGS_DevQueryFlagUpdateResults, _DEV_QUERY_RESULT_ACTION_DevQueryResultAdd,
  _DEV_QUERY_RESULT_ACTION_DevQueryResultUpdate, _DEV_QUERY_STATE_DevQueryStateAborted,
  DEVPROP_FILTER_EXPRESSION, DEV_QUERY_RESULT_ACTION_DATA, HDEVQUERY,
  _DEVPROP_OPERATOR_DEVPROP_OPERATOR_EQUALS, _DEVPROP_OPERATOR_DEVPROP_OPERATOR_EQUALS_IGNORE_CASE,
};
use crate::winapi_ext::swdevicedef::{
  _SW_DEVICE_CAPABILITIES_SWDeviceCapabilitiesDriverRequired,
  _SW_DEVICE_CAPABILITIES_SWDeviceCapabilitiesSilentInstall, SW_DEVICE_CREATE_INFO,
};
use crate::wmain::{NativeMachine, IMAGE_FILE_PROCESS};
// use crate::winapi_ext::devquery::{HDEVQUERY, _DEV_QUERY_RESULT_ACTION_DevQueryResultAdd, _DEV_QUERY_RESULT_ACTION_DevQueryResultUpdate, DEVPROP_FILTER_EXPRESSION, _DEVPROP_OPERATOR_DEVPROP_OPERATOR_EQUALS_IGNORE_CASE};
// use crate::winapi_ext::devquerydef::{DEV_QUERY_RESULT_ACTION_DATA, _DEV_QUERY_STATE_DevQueryStateAborted};

#[macro_export]
macro_rules! WINTUN_HWID_NATIVE {
  () => {
    "Wintun"
  };
}
#[macro_export]
macro_rules! WINTUN_HWID {
  () => {
    widestring::u16cstr!($crate::WINTUN_HWID_NATIVE!())
  };
}
#[macro_export]
macro_rules! WINTUN_ENUMERATOR {
  () => {
    widestring::u16cstr!(concat!("ROOT\\", $crate::WINTUN_HWID_NATIVE!()))
  };
}

pub const DEVPKEY_Wintun_Name: DEVPROPKEY = DEVPROPKEY {
  fmtid: DEVPROPGUID {
    Data1: 0x3361c968,
    Data2: 0x2f2e,
    Data3: 0x4660,
    Data4: [0xb4, 0x7e, 0x69, 0x9c, 0xdc, 0x4c, 0x32, 0xb9],
  },
  pid: DEVPROPID_FIRST_USABLE + 1,
};

static OrphanThreadIsWorking: AtomicBool = AtomicBool::new(false);

pub struct HSWDEVICE__;
pub type HSWDEVICE = *mut HSWDEVICE__;
pub struct WINTUN_ADAPTER {
  SwDevice: HSWDEVICE,
  DevInfo: HDEVINFO,
  DevInfoData: SP_DEVINFO_DATA,
  InterfaceFilename: WideCString,
  CfgInstanceID: GUID,
  DevInstanceID: WideCString,
  LuidIndex: DWORD,
  IfType: DWORD,
  IfIndex: DWORD,
}

pub fn WintunCreateAdapter(
  Name: &WideCStr,
  TunnelType: &WideCStr,
  RequestedGUID: Option<GUID>,
) -> Win32Result<WINTUN_ADAPTER> {
  let mut adapter = WINTUN_ADAPTER {
    InterfaceFilename: Default::default(),
    ..unsafe { InitZeroed::init_zeroed() }
  };
  let dev_install_mutex = SystemNamedMutexLock::take_device_installation_mutex()?;
  let (mut dev_info_existing_adapters, mut existing_adapters) = DriverInstall()?;
  info!("Creating adapter");
  let mut RootNode = unsafe { DEVINST::init_zeroed() };
  let mut RootNodeName = [0 as WCHAR; 200 /* rasmans.dll uses 200 hard coded instead of calling CM_Get_Device_ID_Size. */];
  let result = unsafe {
    CM_Locate_DevNodeW(
      RootNode.get_mut_ptr(),
      std::ptr::null_mut(),
      CM_LOCATE_DEVNODE_NORMAL,
    )
  };
  if result != CR_SUCCESS {
    return Err(error!(
      Win32Error::from_cr(result),
      "Failed to get root node name"
    ));
  }
  let result = unsafe {
    CM_Get_Device_IDW(
      RootNode,
      RootNodeName.as_mut_ptr(),
      RootNodeName.len() as u32,
      0,
    )
  };
  if result != CR_SUCCESS {
    return Err(error!(
      Win32Error::from_cr(result),
      "Failed to get root node name"
    ));
  }
  let mut result = S_OK;
  let instance_id = RequestedGUID.unwrap_or_else(|| {
    let mut guid = unsafe { GUID::init_zeroed() };
    result = unsafe { CoCreateGuid(guid.get_mut_ptr()) };
    guid
  });
  if FAILED(result) {
    return Err(error!(
      Win32Error::new(result as DWORD),
      "Failed to convert GUID"
    ));
  }
  let instance_id_str = [0 as WCHAR; MAX_GUID_STRING_LEN];
  let result = unsafe {
    StringFromGUID2(
      instance_id.get_const_ptr(),
      instance_id_str.as_mut_ptr(),
      instance_id_str.len() as i32,
    )
  };
  if result == FALSE {
    return Err(error!(
      Win32Error::new(ERROR_BUFFER_OVERFLOW),
      "Failed to convert GUID"
    ));
  }

  let mut CreateContext = SW_DEVICE_CREATE_CTX::new(&adapter.DevInstanceID)?;
  #[cfg(Win7)]
  {
    if (!CreateAdapterWin7(Adapter, Name, TunnelTypeName)) {
      LastError = GetLastError();
      // goto cleanupCreateContext;
    }
    // goto skipSwDevice;
  }
  let mut stub_create_info = SW_DEVICE_CREATE_INFO {
    cbSize: csizeof!(SW_DEVICE_CREATE_INFO),
    pszInstanceId: instance_id_str.as_ptr(),
    pszzHardwareIds: widecstr!("").as_ptr(),
    CapabilityFlags: (_SW_DEVICE_CAPABILITIES_SWDeviceCapabilitiesSilentInstall
      | _SW_DEVICE_CAPABILITIES_SWDeviceCapabilitiesDriverRequired) as u32,
    pszDeviceDescription: TunnelType.as_ptr(),
    ..unsafe { std::mem::zeroed() }
  };

  dev_install_mutex.release();
}
pub fn WintunOpenAdapter(Name: &WideCStr) -> Win32Result<WINTUN_ADAPTER> {
  // let mut Adapter: *mut WINTUN_ADAPTER = std::ptr::null_mut();
  // Adapter as *mut _
}
pub fn WintunCloseAdapter(Adapter: &mut WINTUN_ADAPTER) {
  if !Adapter.SwDevice.is_null() {
    unsafe { SwDeviceClose(Adapter.SwDevice) };
  }
  if !Adapter.DevInfo.is_null() {
    if AdapterRemoveInstance(Adapter.DevInfo, Adapter.DevInfoData.get_mut_ptr()).is_err() {
      last_error!("Failed to remove adapter when closing");
    }
    unsafe { SetupDiDestroyDeviceInfoList(Adapter.DevInfo) };
  }
  Free(Adapter.get_mut_ptr().cast_to_pvoid());
  QueueUpOrphanedDeviceCleanupRoutine();
}

pub fn WintunGetAdapterLUID(Adapter: &WINTUN_ADAPTER) -> NET_LUID {
  let mut luid = unsafe { NET_LUID::init_zeroed() };
  luid.set_NetLuidIndex(Adapter.LuidIndex as u64);
  luid.set_IfType(Adapter.IfType as u64);
  luid
}

pub(crate) fn AdapterOpenDeviceObject(Adapter: &WINTUN_ADAPTER) -> Win32Result<HANDLE> {
  let handle = unsafe {
    CreateFileW(
      Adapter.InterfaceFilename.as_ptr(),
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      std::ptr::null_mut(),
      OPEN_EXISTING,
      0,
      std::ptr::null_mut(),
    )
  };
  if !check_handle(handle) {
    return Err(last_error!(
      "Failed to connect to adapter interface {}",
      Adapter.InterfaceFilename.display()
    ));
  }
  Ok(handle)
}

DEFINE_GUID!(
  GUID_DEVINTERFACE_NET,
  0xcac88484,
  0x7515,
  0x4c03,
  0x82,
  0xe6,
  0x71,
  0xa8,
  0x7a,
  0xba,
  0xc3,
  0x61
);

pub(crate) fn AdapterGetDeviceObjectFileName(InstanceId: &WideCStr) -> Win32Result<WideCString> {
  let interface_len = 0;
  let cr = unsafe {
    CM_Get_Device_Interface_List_SizeW(
      interface_len.get_mut_ptr(),
      GUID_DEVINTERFACE_NET.get_mut_ptr(),
      InstanceId.as_ptr() as DEVINSTID_W,
      CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
    )
  };
  let last_error = unsafe { CM_MapCrToWin32Err(cr, ERROR_GEN_FAILURE) };
  if last_error != ERROR_SUCCESS {
    let err = error!(
      Win32Error::new(last_error),
      "Failed to query adapter {} associated instances size",
      InstanceId.display()
    );
    set_last_error(err);
    return Err(err);
  }
  let interfaces = vec![0 as WCHAR; interface_len as usize];
  let cr = unsafe {
    CM_Get_Device_Interface_ListW(
      GUID_DEVINTERFACE_NET.get_mut_ptr(),
      InstanceId.as_ptr() as DEVINSTID_W,
      interfaces.as_mut_ptr(),
      interface_len,
      CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
    )
  };
  let last_error = unsafe { CM_MapCrToWin32Err(cr, ERROR_GEN_FAILURE) };
  if last_error != ERROR_SUCCESS {
    let err = error!(
      Win32Error::new(last_error),
      "Failed to get adapter {} associated instances",
      InstanceId.display()
    );
    set_last_error(err);
    return Err(err);
  }
  WideCString::from_vec(interfaces)
    .ok()
    .ok_or(Win32Error::new(ERROR_DEVICE_NOT_AVAILABLE))
}

#[repr(C)]
pub(crate) struct WAIT_FOR_INTERFACE_CTX {
  Event: HANDLE,
  LastError: DWORD,
}

impl WAIT_FOR_INTERFACE_CTX {
  pub fn new() -> Win32Result<Self> {
    let Event = unsafe { CreateEventW(std::ptr::null_mut(), FALSE, FALSE, std::ptr::null()) };
    if !check_handle(Event) {
      return Err(last_error!("Failed to create event"));
    }
    Ok(Self {
      Event,
      LastError: ERROR_SUCCESS,
    })
  }
}

impl Drop for WAIT_FOR_INTERFACE_CTX {
  fn drop(&mut self) {
    unsafe { CloseHandle(self.Event) };
  }
}

pub(crate) unsafe extern "C" fn WaitForInterfaceCallback(
  DevQuery: HDEVQUERY,
  Context: PVOID,
  ActionData: *const DEV_QUERY_RESULT_ACTION_DATA,
) {
  let Ctx = &mut *(Context as *mut WAIT_FOR_INTERFACE_CTX);
  let ActionData = &*ActionData;
  let mut Ret = ERROR_SUCCESS;
  match ActionData.Action {
    DevQueryResultStateChange => {
      if ActionData.Data.State != _DEV_QUERY_STATE_DevQueryStateAborted {
        return;
      }
      Ret = ERROR_DEVICE_NOT_AVAILABLE;
    }
    _DEV_QUERY_RESULT_ACTION_DevQueryResultAdd | _DEV_QUERY_RESULT_ACTION_DevQueryResultUpdate => {}
    _ => return,
  }
  Ctx.LastError = Ret;
  SetEvent(Ctx.Event);
}

pub(crate) fn WaitForInterface(InstanceId: &WideCStr) -> Win32Result<()> {
  #[cfg(WIN7)]
  return Ok(());
  let sizeof_InstanceId = (InstanceId.len() as DWORD + 1) * 2;
  let InstanceIdPtr = InstanceId.as_ptr() as *mut WCHAR;
  let Filters = [
    DEVPROP_FILTER_EXPRESSION {
      Operator: _DEVPROP_OPERATOR_DEVPROP_OPERATOR_EQUALS_IGNORE_CASE,
      Property: DEVPROPERTY {
        CompKey: DEVPROPCOMPKEY {
          Key: DEVPKEY_Device_InstanceId,
          Store: DEVPROP_STORE_SYSTEM,
          ..unsafe { InitZeroed::init_zeroed() }
        },
        Type: DEVPROP_TYPE_STRING,
        Buffer: InstanceIdPtr.cast_to_pvoid(),
        BufferSize: sizeof_InstanceId,
      },
    },
    DEVPROP_FILTER_EXPRESSION {
      Operator: _DEVPROP_OPERATOR_DEVPROP_OPERATOR_EQUALS,
      Property: DEVPROPERTY {
        CompKey: DEVPROPCOMPKEY {
          Key: DEVPKEY_DeviceInterface_Enabled,
          Store: DEVPROP_STORE_SYSTEM,
          ..unsafe { InitZeroed::init_zeroed() }
        },
        Type: DEVPROP_TYPE_BOOLEAN,
        Buffer: DEVPROP_TRUE.get_pvoid(),
        BufferSize: std::mem::size_of_val(&DEVPROP_TRUE) as DWORD,
      },
    },
    DEVPROP_FILTER_EXPRESSION {
      Operator: _DEVPROP_OPERATOR_DEVPROP_OPERATOR_EQUALS,
      Property: DEVPROPERTY {
        CompKey: DEVPROPCOMPKEY {
          Key: DEVPKEY_DeviceInterface_ClassGuid,
          Store: DEVPROP_STORE_SYSTEM,
          ..unsafe { InitZeroed::init_zeroed() }
        },
        Type: DEVPROP_TYPE_GUID,
        Buffer: GUID_DEVINTERFACE_NET.get_pvoid(),
        BufferSize: std::mem::size_of_val(&GUID_DEVINTERFACE_NET) as DWORD,
      },
    },
  ];
  let Ctx = WAIT_FOR_INTERFACE_CTX::new()?;
  let mut Query = unsafe { HDEVQUERY::init_zeroed() };
  let HRet = unsafe {
    DevCreateObjectQuery(
      _DEV_OBJECT_TYPE_DevObjectTypeDeviceInterface,
      _DEV_QUERY_FLAGS_DevQueryFlagUpdateResults as _,
      0,
      std::ptr::null(),
      Filters.len() as DWORD,
      Filters.as_ptr(),
      Some(WaitForInterfaceCallback),
      Ctx.get_pvoid(),
      Query.get_mut_ptr(),
    )
  };
  if FAILED(HRet) {
    return Err(error!(
      Win32Error::new(HRet as DWORD),
      "Failed to create device query"
    ));
  }
  let cleanupQuery = Defered::new(|| unsafe { DevCloseObjectQuery(Query) });
  let result = unsafe { WaitForSingleObject(Ctx.Event, 15000) };
  if result != WAIT_OBJECT_0 {
    if result == WAIT_FAILED {
      return Err(last_error!("Failed to wait for device query"));
    }
    return Err(error!(
      Win32Error::new(result),
      "Timed out waiting for device query"
    ));
  }
  if Ctx.LastError != ERROR_SUCCESS {
    return Err(error!(
      Win32Error::new(Ctx.LastError),
      "Failed to get enabled device"
    ));
  }
  cleanupQuery.run();
  Ok(())
}

#[repr(C)]
pub(crate) struct SW_DEVICE_CREATE_CTX<'a> {
  CreateResult: HRESULT,
  DeviceInstanceId: Option<&'a WideCStr>,
  Triggered: HANDLE,
}

impl<'a> SW_DEVICE_CREATE_CTX<'a> {
  pub fn new(id: &WideCStr) -> Win32Result<Self> {
    let Triggered = unsafe { CreateEventW(std::ptr::null_mut(), FALSE, FALSE, std::ptr::null()) };
    if !check_handle(Triggered) {
      return Err(last_error!("Failed to create event"));
    }
    Ok(Self {
      CreateResult: 0,
      DeviceInstanceId: Some(id),
      Triggered,
    })
  }
}

impl<'a> Drop for SW_DEVICE_CREATE_CTX<'a> {
  fn drop(&mut self) {
    unsafe { CloseHandle(self.Triggered) };
  }
}

pub(crate) unsafe extern "C" fn DeviceCreateCallback(
  SwDevice: HSWDEVICE,
  CreateResult: HRESULT,
  Context: PVOID,
  DeviceInstanceId: PCWSTR,
) {
  let Ctx = &mut *(Context as *mut SW_DEVICE_CREATE_CTX);
  Ctx.CreateResult = CreateResult;
  if !DeviceInstanceId.is_null() {
    Ctx.DeviceInstanceId = Some(WideCString::from_ptr_truncate(
      DeviceInstanceId,
      MAX_DEVICE_ID_LEN,
    ));
  }
  SetEvent(Ctx.Triggered);
}

pub(crate) fn AdapterRemoveInstance(
  DevInfo: HDEVINFO,
  DevInfoData: *mut SP_DEVINFO_DATA,
) -> Win32Result<()> {
  if unsafe { NativeMachine } != IMAGE_FILE_PROCESS {
    return RemoveInstanceViaRundll32(DevInfo, DevInfoData);
  }
  let RemoveDeviceParams = SP_REMOVEDEVICE_PARAMS {
    ClassInstallHeader: SP_CLASSINSTALL_HEADER {
      cbSize: std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32,
      InstallFunction: DIF_REMOVE,
    },
    Scope: DI_REMOVEDEVICE_GLOBAL,
    ..unsafe { InitZeroed::init_zeroed() }
  };
  let result = unsafe {
    SetupDiSetClassInstallParamsW(
      DevInfo,
      DevInfoData,
      RemoveDeviceParams.ClassInstallHeader.get_mut_ptr(),
      std::mem::size_of_val(&RemoveDeviceParams) as u32,
    )
  };
  if result == FALSE {
    return Err(Win32Error::get_last_error());
  }
  let result = unsafe { SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, DevInfoData) };
  if result == FALSE {
    return Err(Win32Error::get_last_error());
  }
  Ok(())
}
pub(crate) fn AdapterEnableInstance(
  DevInfo: HDEVINFO,
  DevInfoData: *mut SP_DEVINFO_DATA,
) -> Win32Result<()> {
  if NativeMachive != IMAGE_FILE_PROCESS {
    return EnableInstanceViaRundll32(DevInfo, DevInfoData);
  }
  let Params = SP_PROPCHANGE_PARAMS {
    ClassInstallHeader: SP_CLASSINSTALL_HEADER {
      cbSize: std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32,
      InstallFunction: DIF_PROPERTYCHANGE,
    },
    StateChange: DICS_ENABLE,
    Scope: DICS_FLAG_GLOBAL,
    ..unsafe { InitZeroed::init_zeroed() }
  };
  let result = unsafe {
    SetupDiSetClassInstallParamsW(
      DevInfo,
      DevInfoData,
      Params.ClassInstallHeader.get_mut_ptr(),
      std::mem::size_of_val(&Params) as u32,
    )
  };
  if result == FALSE {
    return Err(Win32Error::get_last_error());
  }
  let result = unsafe { SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, DevInfoData) };
  if result == FALSE {
    return Err(Win32Error::get_last_error());
  }
  Ok(())
}

pub(crate) fn AdapterDisableInstance(
  DevInfo: HDEVINFO,
  DevInfoData: *mut SP_DEVINFO_DATA,
) -> Win32Result<()> {
  if NativeMachive != IMAGE_FILE_PROCESS {
    return EnableInstanceViaRundll32(DevInfo, DevInfoData);
  }
  let Params = SP_PROPCHANGE_PARAMS {
    ClassInstallHeader: SP_CLASSINSTALL_HEADER {
      cbSize: std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32,
      InstallFunction: DIF_PROPERTYCHANGE,
    },
    StateChange: DICS_DISABLE,
    Scope: DICS_FLAG_GLOBAL,
    ..unsafe { InitZeroed::init_zeroed() }
  };
  let result = unsafe {
    SetupDiSetClassInstallParamsW(
      DevInfo,
      DevInfoData,
      Params.ClassInstallHeader.get_mut_ptr(),
      std::mem::size_of_val(&Params) as u32,
    )
  };
  if result == FALSE {
    return Err(Win32Error::get_last_error());
  }
  let result = unsafe { SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, DevInfoData) };
  if result == FALSE {
    return Err(Win32Error::get_last_error());
  }
  Ok(())
}

fn PopulateAdapterData(Adapter: &mut WINTUN_ADAPTER) -> Win32Result<()> {
  let mut LastError = ERROR_SUCCESS;

  let Key = RegKey::open(
    Adapter.DevInfo,
    Adapter.DevInfoData.get_mut_ptr(),
    DICS_FLAG_GLOBAL,
    0,
    DIREG_DRV,
    KEY_QUERY_VALUE,
  )?;

  let value_str = RegistryQueryString(&Key, widecstr!("NetCfgInstanceId"), true)?;
  let result = unsafe { CLSIDFromString(value_str.as_ptr(), &mut Adapter.CfgInstanceID) };
  if FAILED(result) {
    let reg_path = LoggerGetRegistryKeyPath(&Key);
    return Err(last_error!(
      "{}\\NetCfgInstanceId is not a GUID: {}",
      reg_path.display(),
      value_str.display()
    ));
  }
  Adapter.LuidIndex = RegistryQueryDWORD(&Key, widecstr!("NetLuidIndex"), true)?;
  Adapter.IfType = RegistryQueryDWORD(&Key, widecstr!("*IfType"), true)?;
  Adapter.InterfaceFilename = AdapterGetDeviceObjectFileName(Adapter.DevInstanceID)?;

  Ok(())
}

fn DoOrphanedDeviceCleanup(Ctx: LPVOID) -> DWORD {
  AdapterCleanupOrphanedDevices();
  OrphanThreadIsWorking.store(false, std::sync::atomic::Ordering::Relaxed);
  return 0;
}

fn QueueUpOrphanedDeviceCleanupRoutine() {
  if OrphanThreadIsWorking
    .compare_exchange(
      false,
      true,
      std::sync::atomic::Ordering::SeqCst,
      std::sync::atomic::Ordering::SeqCst,
    )
    .ignore()
    == false
  {
    QueueUserWorkItem(DoOrphanedDeviceCleanup, std::ptr::null_mut(), 0);
  }
}

pub fn AdapterCleanupOrphanedDevices() {
  let DeviceInstallationMutex = match SystemNamedMutexLock::take_device_installation_mutex() {
    Ok(res) => res,
    Err(_) => {
      last_error!("Failed to take device installation mutex");
      return;
    }
  };

  #[cfg(win7)]
  {
    AdapterCleanupOrphanedDevicesWin7();
    return;
  }

  let DevInfo = unsafe {
    SetupDiGetClassDevsExW(
      &GUID_DEVCLASS_NET,
      WINTUN_ENUMERATOR!().as_ptr(),
      std::ptr::null_mut(),
      0,
      std::ptr::null_mut(),
      std::ptr::null_mut(),
      std::ptr::null_mut(),
    )
  };
  if DevInfo == INVALID_HANDLE_VALUE {
    last_error!("Failed to get adapters");
    return;
  }
  let destroyDeviceInfoList = Defered::new(|| unsafe {
    SetupDiDestroyDeviceInfoList(DevInfo);
  });
  let mut DevInfoData = unsafe {
    SP_DEVINFO_DATA {
      cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as DWORD,
      ..InitZeroed::init_zeroed()
    }
  };
  for EnumIndex in 0.. {
    let result = unsafe { SetupDiEnumDeviceInfo(DevInfo, EnumIndex, DevInfoData.get_mut_ptr()) };
    if result == FALSE {
      if Win32Error::get_last_error().code() == ERROR_NO_MORE_ITEMS {
        break;
      }
      continue;
    }
    let mut Status: ULONG = 0;
    let mut Code: ULONG = 0;
    let result = unsafe {
      CM_Get_DevNode_Status(
        Status.get_mut_ptr(),
        Code.get_mut_ptr(),
        DevInfoData.DevInst,
        0,
      )
    };
    if result == CR_SUCCESS && Status & DN_HAS_PROBLEM == 0 {
      continue;
    }
    let mut PropType = unsafe { DEVPROPTYPE::init_zeroed() };
    let mut Name = wide_array![b"<unknown>"; MAX_ADAPTER_NAME];
    const SIZE_OF_NAME: u32 = (std::mem::size_of::<WCHAR>() * MAX_ADAPTER_NAME) as u32;
    let NamePtr = Name.as_mut_ptr() as *mut u8;
    unsafe {
      SetupDiGetDevicePropertyW(
        DevInfo,
        DevInfoData.get_mut_ptr(),
        DEVPKEY_Wintun_Name.get_const_ptr(),
        PropType.get_mut_ptr(),
        NamePtr,
        SIZE_OF_NAME,
        std::ptr::null_mut(),
        0,
      )
    };
    let result = AdapterRemoveInstance(DevInfo, DevInfoData.get_mut_ptr());
    let Name = WideStr::from_slice(&Name);
    if result.is_err() {
      last_error!("Failed to remove orphaned adapter \"{}\"", Name.display());
      continue;
    }
    log!(
      crate::logger::LogLevel::Info,
      "Removed orphaned adapter \"{}\"",
      Name.display()
    );
  }
  destroyDeviceInfoList.run();
  DeviceInstallationMutex.release();
}

fn RenameByNetGUID(Guid: GUID, Name: &WideCStr) -> Win32Result<()> {
  let DevInfo = unsafe {
    SetupDiGetClassDevsExW(
      GUID_DEVCLASS_NET.get_const_ptr(),
      WINTUN_ENUMERATOR!().as_ptr(),
      std::ptr::null_mut(),
      0,
      std::ptr::null_mut(),
      std::ptr::null_mut(),
      std::ptr::null_mut(),
    )
  };
  if DevInfo == INVALID_HANDLE_VALUE {
    return Win32Error::get_last_error().to_result();
  }
  let destroyDevInfoList = Defered::new(|| {
    unsafe { SetupDiDestroyDeviceInfoList(DevInfo) };
  });
  let DevInfoData = SP_DEVINFO_DATA {
    cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as DWORD,
    ..unsafe { InitZeroed::init_zeroed() }
  };
  for EnumIndex in 0.. {
    let result = unsafe { SetupDiEnumDeviceInfo(DevInfo, EnumIndex, DevInfoData.get_mut_ptr()) };
    if result == FALSE {
      if Win32Error::get_last_error().code() == ERROR_NO_MORE_ITEMS {
        break;
      }
      continue;
    }
    let Key = unsafe {
      SetupDiOpenDevRegKey(
        DevInfo,
        DevInfoData.get_mut_ptr(),
        DICS_FLAG_GLOBAL,
        0,
        DIREG_DRV,
        KEY_QUERY_VALUE,
      )
    };
    if Key.cast_to_pvoid() == INVALID_HANDLE_VALUE {
      continue;
    }
    let Key = RegKey::from_raw(Key);
    let Ok(ValueStr) = RegistryQueryString(&Key, widecstr!("NetCfgInstanceid"), true) else {continue;};
    let Guid2 = unsafe { GUID::init_zeroed() };
    let HRet = unsafe { CLSIDFromString(ValueStr.as_ptr(), Guid2.get_mut_ptr()) };
    if FAILED(HRet) || guid_eq(Guid, Guid2) {
      continue;
    }
    let NameSize = ((Name.len() + 1) * std::mem::size_of::<WCHAR>()) as u32;
    let result = unsafe {
      SetupDiSetDevicePropertyW(
        DevInfo,
        DevInfoData.get_mut_ptr(),
        DEVPKEY_Wintun_Name.get_const_ptr(),
        DEVPROP_TYPE_STRING,
        Name.as_ptr() as *const u8,
        NameSize,
        0,
      )
    };
    if result == FALSE {
      return Win32Error::get_last_error().to_result();
    }
    return Ok(());
  }
  destroyDevInfoList.run();
  set_last_error(Win32Error::new(ERROR_NOT_FOUND));
  Err(last_error!("Failed to get device by GUID: {:?}", Guid))
}

pub fn ConvertInterfaceAliasToGuid(Name: &WideCStr) -> Win32Result<GUID> {
  let mut Luid = unsafe { NET_LUID::init_zeroed() };
  let result = unsafe { ConvertInterfaceAliasToLuid(Name.as_ptr(), Luid.get_mut_ptr()) };
  if result != NO_ERROR {
    set_last_error(Win32Error::new(result));
    return Err(last_error!(
      "Failed convert interface {} name to the locally unique identifier",
      Name.display()
    ));
  }
  let mut Guid = unsafe { GUID::init_zeroed() };
  let result = unsafe { ConvertInterfaceLuidToGuid(Luid.get_const_ptr(), Guid.get_mut_ptr()) };
  if result != NO_ERROR {
    set_last_error(Win32Error::new(result));
    return Err(last_error!(
      "Failed to convert interface {} LUID ({}) to GUID",
      Name.display(),
      Luid.Value
    ));
  }
  Ok(Guid)
}

pub fn NciSetAdapterName(Guid: GUID, Name: &WideCStr) -> Win32Result<WideCString> {
  const MAX_SUFFIX: u32 = 1000;
  if Name.len() >= MAX_ADAPTER_NAME {
    let err = Win32Error::new(ERROR_BUFFER_OVERFLOW);
    set_last_error(err);
    return Err(err);
  }
  let mut avaliable_name = Name.to_owned();
  for i in 0..MAX_SUFFIX {
    match SetConnectionName(Guid, &avaliable_name) {
      Ok(()) => return Ok(avaliable_name),
      Err(err) if err.code() == ERROR_DUP_NAME => {}
      Err(err) => return Err(err),
    };
    todo!("Trying another name is not implemented")
  }
  Err(Win32Error::new(ERROR_DUP_NAME))
}

extern "C" {
  fn SwDeviceClose(hSwDevice: HSWDEVICE);
  // fn CM_MapCrToWin32Err(CmReturnCode: CONFIGRET, DefaultErr: DWORD) -> DWORD;
}
