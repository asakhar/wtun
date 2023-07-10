use std::sync::atomic::AtomicBool;

use cutils::ignore::ResultIgnoreExt;
use cutils::inspection::{CastToMutVoidPtrExt, GetPtrExt, InitZeroed};
use cutils::strings::{StaticWideCStr, WideCStr, WideCString};
use cutils::{
  check_handle, csizeof, defer, guid_eq, unsafe_defer, wide_array, widecstr, GetPvoidExt,
  Win32ErrorFromCrExt, Win32ErrorToResultExt, static_widecstr,
};
use get_last_error::Win32Error;
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
  ERROR_BUFFER_OVERFLOW, ERROR_DEVICE_ENUMERATION_ERROR, ERROR_DEVICE_NOT_AVAILABLE,
  ERROR_DUP_NAME, ERROR_GEN_FAILURE, ERROR_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, FAILED,
  HRESULT, NO_ERROR, S_OK,
};
use winapi::um::cfgmgr32::{
  CM_Get_DevNode_Status, CM_Get_Device_IDW, CM_Get_Device_Interface_ListW,
  CM_Get_Device_Interface_List_SizeW, CM_Locate_DevNodeW, CM_Open_DevNode_Key,
  RegDisposition_OpenAlways, CM_GET_DEVICE_INTERFACE_LIST_PRESENT, CM_LOCATE_DEVINST_PHANTOM,
  CM_LOCATE_DEVNODE_NORMAL, CM_REGISTRY_SOFTWARE, CONFIGRET, CR_SUCCESS, DEVINST, DEVINSTID_W,
  MAX_DEVICE_ID_LEN, MAX_GUID_STRING_LEN,
};
use winapi::um::combaseapi::{CLSIDFromString, CoCreateGuid, StringFromGUID2};
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ipexport::MAX_ADAPTER_NAME;
use winapi::um::setupapi::{
  SetupDiCallClassInstaller, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
  SetupDiGetClassDevsExW, SetupDiOpenDevRegKey, SetupDiSetClassInstallParamsW,
  SetupDiSetDevicePropertyW, DICS_DISABLE, DICS_ENABLE, DIF_PROPERTYCHANGE, DIF_REMOVE,
  DI_REMOVEDEVICE_GLOBAL, ERROR_PNP_REGISTRY_ERROR, SP_CLASSINSTALL_HEADER, SP_PROPCHANGE_PARAMS,
  SP_REMOVEDEVICE_PARAMS,
};
use winapi::um::setupapi::{SetupDiGetDevicePropertyW, DICS_FLAG_GLOBAL};
use winapi::um::setupapi::{DIREG_DRV, HDEVINFO, SP_DEVINFO_DATA};
use winapi::um::synchapi::{CreateEventW, SetEvent, WaitForSingleObject};
use winapi::um::threadpoollegacyapiset::QueueUserWorkItem;
use winapi::um::winbase::{INFINITE, WAIT_FAILED, WAIT_OBJECT_0};
use winapi::um::winnt::{
  FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE,
  KEY_QUERY_VALUE, KEY_SET_VALUE, PVOID, REG_BINARY, WCHAR,
};
use winapi::um::winreg::RegSetValueExW;
use winapi::DEFINE_GUID;

use crate::driver::DriverInstall;
use crate::logger::LoggerGetRegistryKeyPath;
use crate::logger::{error, info, last_error, log, warn};
use crate::namespace::SystemNamedMutexLock;
use crate::nci::SetConnectionName;
use crate::registry::{RegKey, RegistryQueryDWORD, RegistryQueryString};
use crate::rundll32::{remove_instance, enable_instance};
use crate::winapi_ext::devquery::{
  DevCloseObjectQuery, DevCreateObjectQuery, _DEV_OBJECT_TYPE_DevObjectTypeDeviceInterface,
  _DEV_QUERY_FLAGS_DevQueryFlagUpdateResults, _DEV_QUERY_RESULT_ACTION_DevQueryResultAdd,
  _DEV_QUERY_RESULT_ACTION_DevQueryResultUpdate, _DEV_QUERY_STATE_DevQueryStateAborted,
  DEVPROP_FILTER_EXPRESSION, DEV_QUERY_RESULT_ACTION_DATA, HDEVQUERY,
  _DEVPROP_OPERATOR_DEVPROP_OPERATOR_EQUALS, _DEVPROP_OPERATOR_DEVPROP_OPERATOR_EQUALS_IGNORE_CASE,
};
use crate::winapi_ext::swdevice::{
  SwDeviceClose, SwDeviceCreate, _SW_DEVICE_CAPABILITIES_SWDeviceCapabilitiesDriverRequired,
  _SW_DEVICE_CAPABILITIES_SWDeviceCapabilitiesSilentInstall, HSWDEVICE, PHSWDEVICE,
  SW_DEVICE_CREATE_INFO,
};
// use crate::winapi_ext::swdevice::{
//   _SW_DEVICE_CAPABILITIES_SWDeviceCapabilitiesDriverRequired,
//   _SW_DEVICE_CAPABILITIES_SWDeviceCapabilitiesSilentInstall, SW_DEVICE_CREATE_INFO,
// };
use crate::wmain::{IMAGE_FILE_PROCESS, get_system_params};
// use crate::winapi_ext::devquery::{HDEVQUERY, _DEV_QUERY_RESULT_ACTION_DevQueryResultAdd, _DEV_QUERY_RESULT_ACTION_DevQueryResultUpdate, DEVPROP_FILTER_EXPRESSION, _DEVPROP_OPERATOR_DEVPROP_OPERATOR_EQUALS_IGNORE_CASE};
// use crate::winapi_ext::devquerydef::{DEV_QUERY_RESULT_ACTION_DATA, _DEV_QUERY_STATE_DevQueryStateAborted};

pub(crate) const WINTUN_HWID: &WideCStr = widecstr!("Wintun");
pub(crate) const WINTUN_ENUMERATOR: &WideCStr = widecstr!(r"ROOT\Wintun");

pub(crate) const DEVPKEY_Wintun_Name: DEVPROPKEY = DEVPROPKEY {
  fmtid: DEVPROPGUID {
    Data1: 0x3361c968,
    Data2: 0x2f2e,
    Data3: 0x4660,
    Data4: [0xb4, 0x7e, 0x69, 0x9c, 0xdc, 0x4c, 0x32, 0xb9],
  },
  pid: DEVPROPID_FIRST_USABLE + 1,
};

static OrphanThreadIsWorking: AtomicBool = AtomicBool::new(false);

pub struct WINTUN_ADAPTER {
  pub(crate) SwDevice: HSWDEVICE,
  pub(crate) DevInfo: HDEVINFO,
  pub(crate) DevInfoData: SP_DEVINFO_DATA,
  pub(crate) InterfaceFilename: WideCString,
  pub(crate) CfgInstanceID: GUID,
  pub(crate) DevInstanceID: StaticWideCStr<MAX_DEVICE_ID_LEN>,
  pub(crate) LuidIndex: DWORD,
  pub(crate) IfType: DWORD,
  pub(crate) IfIndex: DWORD,
}

pub fn WintunCreateAdapter(
  name: &WideCStr,
  tunnel_type: &WideCStr,
  requested_guid: Option<GUID>,
) -> std::io::Result<WINTUN_ADAPTER> {
  let mut adapter = WINTUN_ADAPTER {
    InterfaceFilename: Default::default(),
    DevInstanceID: Default::default(),
    ..unsafe { InitZeroed::init_zeroed() }
  };
  let dev_install_mutex = SystemNamedMutexLock::take_device_installation_mutex()?;
  let (mut dev_info_existing_adapters, mut existing_adapters) = DriverInstall()?;
  info!("Creating adapter");
  let mut root_node = unsafe { DEVINST::init_zeroed() };
  let mut root_node_name = StaticWideCStr::<200>::zeroed() /* rasmans.dll uses 200 hard coded instead of calling CM_Get_Device_ID_Size. */;
  let result = unsafe {
    CM_Locate_DevNodeW(
      root_node.get_mut_ptr(),
      std::ptr::null_mut(),
      CM_LOCATE_DEVNODE_NORMAL,
    )
  };
  if result != CR_SUCCESS {
    return Err(error!(
      Win32Error::from_cr(result, ERROR_GEN_FAILURE),
      "Failed to get root node name"
    ));
  }
  let result = unsafe {
    CM_Get_Device_IDW(
      root_node,
      root_node_name.as_mut_ptr(),
      root_node_name.len(),
      0,
    )
  };
  if result != CR_SUCCESS {
    return Err(error!(
      Win32Error::from_cr(result, ERROR_GEN_FAILURE),
      "Failed to get root node name"
    ));
  }
  let mut result = S_OK;
  let instance_id = requested_guid.unwrap_or_else(|| {
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
  let mut instance_id_str = StaticWideCStr::<MAX_GUID_STRING_LEN>::zeroed();
  let result = unsafe {
    StringFromGUID2(
      instance_id.get_const_ptr(),
      instance_id_str.as_mut_ptr(),
      instance_id_str.len(),
    )
  };
  if result == FALSE {
    return Err(error!(
      Win32Error::new(ERROR_BUFFER_OVERFLOW),
      "Failed to convert GUID"
    ));
  }

  let mut create_context = SW_DEVICE_CREATE_CTX::new(adapter.DevInstanceID.as_ref())?;
  #[cfg(Win7)]
  {
    if (!CreateAdapterWin7(Adapter, name, TunnelTypeName)) {
      LastError = GetLastError();
      // goto cleanupCreateContext;
    }
    // goto skipSwDevice;
  }
  WintunCreateAdapterStub(
    instance_id,
    &instance_id_str,
    tunnel_type,
    &root_node_name,
    &mut create_context,
    &mut adapter,
  )?;
  let hwids = static_widecstr!("Wintun"; {WINTUN_HWID.len_usize()+1});
  let create_info = SW_DEVICE_CREATE_INFO {
    cbSize: csizeof!(SW_DEVICE_CREATE_INFO),
    pszInstanceId: instance_id_str.as_ptr(),
    pszzHardwareIds: hwids.as_ptr(),
    CapabilityFlags: (_SW_DEVICE_CAPABILITIES_SWDeviceCapabilitiesSilentInstall
      | _SW_DEVICE_CAPABILITIES_SWDeviceCapabilitiesDriverRequired) as _,
    pszDeviceDescription: tunnel_type.as_ptr(),
    ..unsafe { core::mem::zeroed() }
  };
  // --------------------
  dev_install_mutex.release();
  todo!()
}
fn WintunCreateAdapterStub(
  instance_id: GUID,
  instance_id_str: &WideCStr,
  tunnel_type: &WideCStr,
  root_node_name: &WideCStr,
  create_context: &mut SW_DEVICE_CREATE_CTX,
  adapter: &mut WINTUN_ADAPTER,
) -> std::io::Result<()> {
  let mut stub_create_info = SW_DEVICE_CREATE_INFO {
    cbSize: csizeof!(SW_DEVICE_CREATE_INFO),
    pszInstanceId: instance_id_str.as_ptr(),
    pszzHardwareIds: widecstr!("").as_ptr(),
    CapabilityFlags: (_SW_DEVICE_CAPABILITIES_SWDeviceCapabilitiesSilentInstall
      | _SW_DEVICE_CAPABILITIES_SWDeviceCapabilitiesDriverRequired) as u32,
    pszDeviceDescription: tunnel_type.as_ptr(),
    ..unsafe { std::mem::zeroed() }
  };
  let mut stub_device_properties = [DEVPROPERTY {
    CompKey: DEVPROPCOMPKEY {
      Key: DEVPKEY_DeviceInterface_ClassGuid,
      Store: DEVPROP_STORE_SYSTEM,
      ..unsafe { core::mem::zeroed() }
    },
    Type: DEVPROP_TYPE_GUID,
    Buffer: GUID_DEVCLASS_NET.get_pvoid(),
    BufferSize: csizeof!(=GUID_DEVCLASS_NET),
  }];

  let hret = unsafe {
    SwDeviceCreate(
      WINTUN_HWID.as_ptr(),
      root_node_name.as_ptr(),
      stub_create_info.get_const_ptr(),
      stub_device_properties.len() as u32,
      stub_device_properties.as_ptr(),
      Some(DeviceCreateCallback),
      create_context.get_pvoid(),
      adapter.SwDevice.get_mut_ptr(),
    )
  };
  if FAILED(hret) {
    return Err(error!(hret, "Failed to initiate stub device creation"));
  }
  let res = unsafe { WaitForSingleObject(create_context.Triggered, INFINITE) };
  if res != WAIT_OBJECT_0 {
    return Err(last_error!(
      "Failed to wait for stub device creation trigger"
    ));
  }
  if FAILED(create_context.CreateResult) {
    return Err(error!(
      Win32Error::new(create_context.CreateResult as u32),
      "Failed to create stub device"
    ));
  }
  let mut dev_inst = unsafe { DEVINST::init_zeroed() };
  let cret = unsafe {
    CM_Locate_DevNodeW(
      dev_inst.get_mut_ptr(),
      adapter.DevInstanceID.as_mut_ptr(),
      CM_LOCATE_DEVINST_PHANTOM,
    )
  };
  if cret != CR_SUCCESS {
    return Err(error!(
      Win32Error::from_cr(cret, ERROR_DEVICE_ENUMERATION_ERROR),
      "Failed to make stub device list"
    ));
  }
  let mut driver_key = unsafe { HKEY::init_zeroed() };
  let cret = unsafe {
    CM_Open_DevNode_Key(
      dev_inst,
      KEY_SET_VALUE,
      0,
      RegDisposition_OpenAlways,
      driver_key.get_mut_ptr(),
      CM_REGISTRY_SOFTWARE,
    )
  };
  let driver_key = RegKey::from_raw(driver_key);
  if cret != CR_SUCCESS {
    return Err(error!(
      Win32Error::from_cr(cret, ERROR_PNP_REGISTRY_ERROR),
      "Failed to create software registry key"
    ));
  }
  let res = unsafe {
    RegSetValueExW(
      driver_key.as_raw(),
      widecstr!("SuggestedInstanceId").as_ptr(),
      0,
      REG_BINARY,
      instance_id.get_const_ptr() as *const _,
      csizeof!(=instance_id),
    )
  } as u32;
  driver_key.close();
  if res != ERROR_SUCCESS {
    return Err(error!(
      res,
      "Failed to set SuggestedInstanceId to {}",
      instance_id_str.display()
    ));
  }
  unsafe {
    SwDeviceClose(adapter.SwDevice);
  }
  adapter.SwDevice = std::ptr::null_mut();
  Ok(())
}
pub fn WintunOpenAdapter(Name: &WideCStr) -> std::io::Result<WINTUN_ADAPTER> {
  // let mut Adapter: *mut WINTUN_ADAPTER = std::ptr::null_mut();
  // Adapter as *mut _
  todo!()
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
  // Free(Adapter.get_mut_ptr().cast_to_pvoid());
  QueueUpOrphanedDeviceCleanupRoutine();
}

pub fn WintunGetAdapterLUID(Adapter: &WINTUN_ADAPTER) -> NET_LUID {
  let mut luid = unsafe { NET_LUID::init_zeroed() };
  luid.set_NetLuidIndex(Adapter.LuidIndex as u64);
  luid.set_IfType(Adapter.IfType as u64);
  luid
}

pub(crate) fn AdapterOpenDeviceObject(Adapter: &WINTUN_ADAPTER) -> std::io::Result<HANDLE> {
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

pub(crate) fn AdapterGetDeviceObjectFileName(
  InstanceId: &WideCStr,
) -> std::io::Result<WideCString> {
  let mut interface_len = 0;
  let cr = unsafe {
    CM_Get_Device_Interface_List_SizeW(
      interface_len.get_mut_ptr(),
      GUID_DEVINTERFACE_NET.get_mut_ptr(),
      InstanceId.as_ptr() as DEVINSTID_W,
      CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
    )
  };
  if let Err(err) = Win32Error::from_cr(cr, ERROR_GEN_FAILURE).to_result() {
    let err = error!(
      err,
      "Failed to query adapter {} associated instances size",
      InstanceId.display()
    );
    return Err(err);
  }
  let mut interfaces = vec![0 as WCHAR; interface_len as usize];
  let cr = unsafe {
    CM_Get_Device_Interface_ListW(
      GUID_DEVINTERFACE_NET.get_mut_ptr(),
      InstanceId.as_ptr() as DEVINSTID_W,
      interfaces.as_mut_ptr(),
      interface_len,
      CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
    )
  };
  if let Err(err) = Win32Error::from_cr(cr, ERROR_GEN_FAILURE).to_result() {
    let err = error!(
      err,
      "Failed to get adapter {} associated instances",
      InstanceId.display()
    );
    return Err(err);
  }
  Ok(WideCString::from(interfaces))
}

#[repr(C)]
pub(crate) struct WAIT_FOR_INTERFACE_CTX {
  Event: HANDLE,
  LastError: DWORD,
}

impl WAIT_FOR_INTERFACE_CTX {
  pub fn new() -> std::io::Result<Self> {
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

pub(crate) fn WaitForInterface(InstanceId: &WideCStr) -> std::io::Result<()> {
  #[cfg(WIN7)]
  return Ok(());
  let len_instance_id: DWORD = InstanceId.len();
  let sizeof_InstanceId = (len_instance_id + 1) * 2;
  let InstanceIdPtr = unsafe { InstanceId.as_mut_ptr_bypass() };
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
        Buffer: InstanceIdPtr.cast(),
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
      HRet,
      "Failed to create device query"
    ));
  }
  defer! { cleanupQuery <-
    unsafe { DevCloseObjectQuery(Query) }
  };
  let result = unsafe { WaitForSingleObject(Ctx.Event, 15000) };
  if result != WAIT_OBJECT_0 {
    if result == WAIT_FAILED {
      return Err(last_error!("Failed to wait for device query"));
    }
    return Err(error!(
      result,
      "Timed out waiting for device query"
    ));
  }
  if Ctx.LastError != ERROR_SUCCESS {
    return Err(error!(
      Ctx.LastError,
      "Failed to get enabled device"
    ));
  }
  cleanupQuery.run();
  Ok(())
}

#[repr(C)]
pub(crate) struct SW_DEVICE_CREATE_CTX {
  CreateResult: HRESULT,
  DeviceInstanceId: Option<WideCString>,
  Triggered: HANDLE,
}

impl SW_DEVICE_CREATE_CTX {
  pub fn new(id: &WideCStr) -> std::io::Result<Self> {
    let Triggered = unsafe { CreateEventW(std::ptr::null_mut(), FALSE, FALSE, std::ptr::null()) };
    if !check_handle(Triggered) {
      return Err(last_error!("Failed to create event"));
    }
    Ok(Self {
      CreateResult: 0,
      DeviceInstanceId: Some(id.into()),
      Triggered,
    })
  }
}

impl Drop for SW_DEVICE_CREATE_CTX {
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
) -> std::io::Result<()> {
  if unsafe { get_system_params().NativeMachine } != IMAGE_FILE_PROCESS {
    return remove_instance(DevInfo, DevInfoData);
  }
  let mut RemoveDeviceParams = SP_REMOVEDEVICE_PARAMS {
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
    return Err(std::io::Error::last_os_error());
  }
  let result = unsafe { SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, DevInfoData) };
  if result == FALSE {
    return Err(std::io::Error::last_os_error());
  }
  Ok(())
}
pub(crate) fn AdapterEnableInstance(
  DevInfo: HDEVINFO,
  DevInfoData: *mut SP_DEVINFO_DATA,
) -> std::io::Result<()> {
  if unsafe { get_system_params().NativeMachine } != IMAGE_FILE_PROCESS {
    return enable_instance(DevInfo, DevInfoData);
  }
  let mut Params = SP_PROPCHANGE_PARAMS {
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
    return Err(std::io::Error::last_os_error());
  }
  let result = unsafe { SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, DevInfoData) };
  if result == FALSE {
    return Err(std::io::Error::last_os_error());
  }
  Ok(())
}

pub(crate) fn AdapterDisableInstance(
  DevInfo: HDEVINFO,
  DevInfoData: *mut SP_DEVINFO_DATA,
) -> std::io::Result<()> {
  if unsafe { get_system_params().NativeMachine } != IMAGE_FILE_PROCESS {
    return enable_instance(DevInfo, DevInfoData);
  }
  let mut Params = SP_PROPCHANGE_PARAMS {
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
    return Err(std::io::Error::last_os_error());
  }
  let result = unsafe { SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, DevInfoData) };
  if result == FALSE {
    return Err(std::io::Error::last_os_error());
  }
  Ok(())
}

fn PopulateAdapterData(Adapter: &mut WINTUN_ADAPTER) -> std::io::Result<()> {
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
  Adapter.InterfaceFilename = AdapterGetDeviceObjectFileName(Adapter.DevInstanceID.as_ref())?;

  Ok(())
}

unsafe extern "system" fn DoOrphanedDeviceCleanup(Ctx: LPVOID) -> DWORD {
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
    unsafe { QueueUserWorkItem(Some(DoOrphanedDeviceCleanup), std::ptr::null_mut(), 0) };
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
      WINTUN_ENUMERATOR.as_ptr(),
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
  unsafe_defer! { destroyDeviceInfoList <-
    SetupDiDestroyDeviceInfoList(DevInfo);
  };
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
    let mut Name = wide_array!["<unknown>"; MAX_ADAPTER_NAME];
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
    let Name: &WideCStr = unsafe { Name.as_ref().try_into() }.unwrap_or(widecstr!("<unknown>"));
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

fn RenameByNetGUID(Guid: GUID, Name: &WideCStr) -> std::io::Result<()> {
  let DevInfo = unsafe {
    SetupDiGetClassDevsExW(
      GUID_DEVCLASS_NET.get_const_ptr(),
      WINTUN_ENUMERATOR.as_ptr(),
      std::ptr::null_mut(),
      0,
      std::ptr::null_mut(),
      std::ptr::null_mut(),
      std::ptr::null_mut(),
    )
  };
  if DevInfo == INVALID_HANDLE_VALUE {
    return Err(std::io::Error::last_os_error());
  }
  unsafe_defer! { destroyDevInfoList <-
    SetupDiDestroyDeviceInfoList(DevInfo) ;
  };
  let mut DevInfoData = SP_DEVINFO_DATA {
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
    let mut Guid2 = unsafe { GUID::init_zeroed() };
    let HRet = unsafe { CLSIDFromString(ValueStr.as_ptr(), Guid2.get_mut_ptr()) };
    if FAILED(HRet) || guid_eq(Guid, Guid2) {
      continue;
    }
    let NameSize = Name.capacity();
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
      return Err(std::io::Error::last_os_error());
    }
    return Ok(());
  }
  destroyDevInfoList.run();
  Err(error!(
    Win32Error::new(ERROR_NOT_FOUND),
    "Failed to get device by GUID: {:?}", Guid
  ))
}

pub fn ConvertInterfaceAliasToGuid(Name: &WideCStr) -> std::io::Result<GUID> {
  let mut Luid = unsafe { NET_LUID::init_zeroed() };
  let result = unsafe { ConvertInterfaceAliasToLuid(Name.as_ptr(), Luid.get_mut_ptr()) };
  if result != NO_ERROR {
    return Err(error!(
      Win32Error::new(result),
      "Failed convert interface {} name to the locally unique identifier",
      Name.display()
    ));
  }
  let mut Guid = unsafe { GUID::init_zeroed() };
  let result = unsafe { ConvertInterfaceLuidToGuid(Luid.get_const_ptr(), Guid.get_mut_ptr()) };
  if result != NO_ERROR {
    return Err(error!(
      Win32Error::new(result),
      "Failed to convert interface {} LUID ({}) to GUID",
      Name.display(),
      Luid.Value
    ));
  }
  Ok(Guid)
}

pub fn NciSetAdapterName(Guid: GUID, Name: &WideCStr) -> std::io::Result<WideCString> {
  const MAX_SUFFIX: u32 = 1000;
  if Name.len_usize() >= MAX_ADAPTER_NAME {
    let err = std::io::Error::from_raw_os_error(ERROR_BUFFER_OVERFLOW as i32);
    return Err(err);
  }
  let mut avaliable_name = Name.to_owned();
  for i in 0..MAX_SUFFIX {
    match SetConnectionName(Guid, avaliable_name.as_ref()) {
      Ok(()) => return Ok(avaliable_name),
      Err(err) if err.raw_os_error().unwrap() == ERROR_DUP_NAME as i32 => {}
      Err(err) => return Err(err),
    };
    todo!("Trying another name is not implemented")
  }
  Err(std::io::Error::from_raw_os_error(ERROR_DUP_NAME as i32))
}
