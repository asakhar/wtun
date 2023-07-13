use std::pin::Pin;
use std::ptr::null_mut;
use std::sync::atomic::AtomicBool;

use cutils::ignore::ResultIgnoreExt;
use cutils::inspection::{CastToMutVoidPtrExt, GetPtrExt, InitZeroed};
use cutils::strings::{StaticWideCStr, WideCStr, WideCString};
use cutils::{
  check_handle, csizeof, defer, guid_eq, static_widecstr, unsafe_defer, wide_array, widecstr,
  Win32ErrorFromCrExt, Win32ErrorToResultExt,
};
use get_last_error::Win32Error;
use winapi::shared::basetsd::INT32;
use winapi::shared::cfg::DN_HAS_PROBLEM;
use winapi::shared::devguid::GUID_DEVCLASS_NET;
use winapi::shared::devpkey::{
  DEVPKEY_DeviceInterface_ClassGuid, DEVPKEY_DeviceInterface_Enabled, DEVPKEY_Device_ClassGuid,
  DEVPKEY_Device_DeviceDesc, DEVPKEY_Device_FriendlyName, DEVPKEY_Device_InstanceId,
  DEVPKEY_Device_ProblemCode, DEVPKEY_Device_ProblemStatus,
};
use winapi::shared::devpropdef::{
  DEVPROPCOMPKEY, DEVPROPERTY, DEVPROPGUID, DEVPROPID_FIRST_USABLE, DEVPROPKEY, DEVPROPTYPE,
  DEVPROP_STORE_SYSTEM, DEVPROP_TRUE, DEVPROP_TYPE_BOOLEAN, DEVPROP_TYPE_GUID, DEVPROP_TYPE_INT32,
  DEVPROP_TYPE_NTSTATUS, DEVPROP_TYPE_STRING, DEVPROP_TYPE_UINT32,
};
use winapi::shared::guiddef::GUID;
use winapi::shared::ifdef::NET_LUID;
use winapi::shared::minwindef::{DWORD, LPVOID, TRUE};
use winapi::shared::minwindef::{FALSE, HKEY, ULONG};
use winapi::shared::netioapi::{ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToGuid};
use winapi::shared::ntdef::{HANDLE, NTSTATUS, PCWSTR};
use winapi::shared::winerror::{
  ERROR_BUFFER_OVERFLOW, ERROR_DEVICE_ENUMERATION_ERROR, ERROR_DEVICE_NOT_AVAILABLE,
  ERROR_DUP_NAME, ERROR_GEN_FAILURE, ERROR_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, FAILED,
  HRESULT, NO_ERROR, S_OK,
};
use winapi::um::cfgmgr32::{
  CM_Get_DevNode_Status, CM_Get_Device_IDW, CM_Get_Device_Interface_ListW,
  CM_Get_Device_Interface_List_SizeW, CM_Locate_DevNodeW, CM_Open_DevNode_Key,
  RegDisposition_OpenAlways, CM_GET_DEVICE_INTERFACE_LIST_PRESENT, CM_LOCATE_DEVINST_PHANTOM,
  CM_LOCATE_DEVNODE_NORMAL, CM_REGISTRY_SOFTWARE, CR_SUCCESS, DEVINST, DEVINSTID_W,
  MAX_DEVICE_ID_LEN, MAX_GUID_STRING_LEN,
};
use winapi::um::combaseapi::{CLSIDFromString, CoCreateGuid, StringFromGUID2};
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ipexport::MAX_ADAPTER_NAME;
use winapi::um::setupapi::{
  SetupDiCallClassInstaller, SetupDiCreateDeviceInfoListExW, SetupDiDestroyDeviceInfoList,
  SetupDiEnumDeviceInfo, SetupDiGetClassDevsExW, SetupDiGetDeviceInstanceIdW, SetupDiOpenDevRegKey,
  SetupDiOpenDeviceInfoW, SetupDiSetClassInstallParamsW, SetupDiSetDevicePropertyW, DICS_DISABLE,
  DICS_ENABLE, DIF_PROPERTYCHANGE, DIF_REMOVE, DIGCF_PRESENT, DIOD_INHERIT_CLASSDRVS,
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

use crate::RingCapacity;
use crate::adapter_win7::{create_adapter_post_win7, create_adapter_win7};
use crate::driver::{DriverInstall, DriverInstallDeferredCleanup};
use crate::logger::LoggerGetRegistryKeyPath;
use crate::logger::{error, info, last_error, log};
use crate::namespace::SystemNamedMutexLock;
use crate::nci::SetConnectionName;
use crate::registry::{RegKey, RegistryQueryDWORD, RegistryQueryString};
use crate::rundll32::{enable_instance, remove_instance};
use crate::session::{Session, WintunStartSession};
use crate::winapi_ext::devquery::{
  DevCloseObjectQuery, DevCreateObjectQuery, _DEV_OBJECT_TYPE_DevObjectTypeDeviceInterface,
  _DEV_QUERY_FLAGS_DevQueryFlagUpdateResults, _DEV_QUERY_RESULT_ACTION_DevQueryResultAdd,
  _DEV_QUERY_RESULT_ACTION_DevQueryResultStateChange,
  _DEV_QUERY_RESULT_ACTION_DevQueryResultUpdate, _DEV_QUERY_STATE_DevQueryStateAborted,
  DEVPROP_FILTER_EXPRESSION, DEV_QUERY_RESULT_ACTION_DATA, HDEVQUERY,
  _DEVPROP_OPERATOR_DEVPROP_OPERATOR_EQUALS, _DEVPROP_OPERATOR_DEVPROP_OPERATOR_EQUALS_IGNORE_CASE,
};
use crate::winapi_ext::swdevice::{
  SwDeviceClose, SwDeviceCreate, _SW_DEVICE_CAPABILITIES_SWDeviceCapabilitiesDriverRequired,
  _SW_DEVICE_CAPABILITIES_SWDeviceCapabilitiesSilentInstall, HSWDEVICE, SW_DEVICE_CREATE_INFO,
};
use crate::winapi_ext::winternl::RtlNtStatusToDosError;
use crate::wmain::{get_system_params, IMAGE_FILE_PROCESS};

pub(crate) const WINTUN_HWID: &WideCStr = widecstr!("Wintun");
macro_rules! WINTUN_ENUMERATOR {
  () => {
    if unsafe { $crate::wmain::get_system_params() }.IsWindows7 {
      widecstr!(r"ROOT\Wintun")
    } else {
      widecstr!(r"SWD\Wintun")
    }
  }
}
pub(crate) use WINTUN_ENUMERATOR;

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

pub struct Adapter {
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

impl Adapter {
  pub fn create(
    name: &str,
    tunnel_type: &str,
    requested_guid: Option<GUID>,
  ) -> std::io::Result<Adapter> {
    let name: StaticWideCStr<MAX_ADAPTER_NAME> = cutils::strings::encode(name).ok_or(
      std::io::Error::new(std::io::ErrorKind::InvalidInput, "Tunnel name is too long"),
    )?;
    let tunnel_type: StaticWideCStr<MAX_ADAPTER_NAME> = cutils::strings::encode(tunnel_type)
      .ok_or(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "Tunnel type is too long",
      ))?;
    WintunCreateAdapter(&name, &tunnel_type, requested_guid)
  }
  pub fn open(name: &str) -> std::io::Result<Adapter> {
    let name: StaticWideCStr<MAX_ADAPTER_NAME> = cutils::strings::encode(name).ok_or(
      std::io::Error::new(std::io::ErrorKind::InvalidInput, "Tunnel name is too long"),
    )?;
    WintunOpenAdapter(&name)
  }
  pub fn close(self) {
    drop(self)
  }
  pub fn get_luid(&self) -> NET_LUID {
    WintunGetAdapterLUID(self)
  }
  pub fn get_guid(&self) -> GUID{
    self.CfgInstanceID
  }
  pub fn start_session(&mut self, capacity: RingCapacity) -> std::io::Result<Pin<Box<Session>>> {
    WintunStartSession(self, capacity.0)
  }
}

impl Drop for Adapter {
  fn drop(&mut self) {
    WintunCloseAdapter(self)
  }
}

pub fn WintunCreateAdapter(
  name: &StaticWideCStr<MAX_ADAPTER_NAME>,
  tunnel_type: &StaticWideCStr<MAX_ADAPTER_NAME>,
  requested_guid: Option<GUID>,
) -> std::io::Result<Adapter> {
  let _system_params = unsafe { get_system_params() };
  unsafe_defer! { cleanup <-
    QueueUpOrphanedDeviceCleanupRoutine();
  };
  let dev_install_mutex = match SystemNamedMutexLock::take_device_installation_mutex() {
    Ok(res) => res,
    Err(err) => return Err(error!(err, "Failed to take device installation mutex")), // cleanup
  };
  let (dev_info_existing_adapters, mut existing_adapters) = DriverInstall()?; // cleanupDeviceInstallationMutex
  info!("Creating adapter");
  let mut adapter = Adapter {
    InterfaceFilename: Default::default(),
    DevInstanceID: Default::default(),
    SwDevice: null_mut(),
    DevInfo: null_mut(),
    DevInfoData: unsafe { std::mem::zeroed() },
    CfgInstanceID: unsafe { std::mem::zeroed() },
    LuidIndex: 0,
    IfType: 0,
    IfIndex: 0,
  };
  unsafe_defer! { cleanupDriverInstall <-
    DriverInstallDeferredCleanup(dev_info_existing_adapters, &mut existing_adapters);
  };
  let adapter_ptr = adapter.get_mut_ptr();
  unsafe_defer! { cleanupAdapter <-
    WintunCloseAdapter(&mut *adapter_ptr)
  };
  let mut root_node: DEVINST = 0;
  let mut root_node_name = StaticWideCStr::<200>::zeroed() /* rasmans.dll uses 200 hard coded instead of calling CM_Get_Device_ID_Size. */;
  let result = unsafe {
    CM_Locate_DevNodeW(
      root_node.get_mut_ptr(),
      null_mut(),
      CM_LOCATE_DEVNODE_NORMAL,
    )
  };
  if result != CR_SUCCESS {
    return Err(error!(
      Win32Error::from_cr(result, ERROR_GEN_FAILURE),
      "Failed to locate root node name"
    ));
  }
  let result = unsafe {
    CM_Get_Device_IDW(
      root_node,
      root_node_name.as_mut_ptr(),
      root_node_name.capacity(),
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
    let mut guid: GUID = unsafe { std::mem::zeroed() };
    result = unsafe { CoCreateGuid(guid.get_mut_ptr()) };
    guid
  });
  if FAILED(result) {
    return Err(error!(result, "Failed to create GUID"));
  }
  let mut instance_id_str = StaticWideCStr::<MAX_GUID_STRING_LEN>::zeroed();
  let result = unsafe {
    StringFromGUID2(
      instance_id.get_const_ptr(),
      instance_id_str.as_mut_ptr(),
      MAX_GUID_STRING_LEN as i32,
    )
  };
  if result == FALSE {
    return Err(last_error!("Failed to convert GUID"));
  }

  let mut create_context = SW_DEVICE_CREATE_CTX::new(&mut adapter.DevInstanceID)?;
  let system_params = unsafe { get_system_params() };
  if system_params.IsWindows7 {
    create_adapter_win7(&mut adapter, &name, &tunnel_type)?;
    // goto skipSwDevice
  } else {
    if system_params.IsWindows10 {
      WintunCreateAdapterStub(
        instance_id,
        &instance_id_str,
        &tunnel_type,
        &root_node_name,
        &mut create_context,
        &mut adapter,
      )?;
    }
    WintunCreateAdapterSwDevice(
      &instance_id_str,
      &name,
      &tunnel_type,
      &root_node_name,
      &mut create_context,
      &mut adapter,
    )?;
  }
  adapter.DevInfo = unsafe {
    SetupDiCreateDeviceInfoListExW(
      GUID_DEVCLASS_NET.get_const_ptr(),
      null_mut(),
      null_mut(),
      null_mut(),
    )
  };
  if !check_handle(adapter.DevInfo) {
    adapter.DevInfo = null_mut();
    return Err(last_error!("Failed to make device list"));
  }
  adapter.DevInfoData.cbSize = csizeof!(=adapter.DevInfoData);
  let res = unsafe {
    SetupDiOpenDeviceInfoW(
      adapter.DevInfo,
      adapter.DevInstanceID.as_ptr(),
      null_mut(),
      DIOD_INHERIT_CLASSDRVS,
      adapter.DevInfoData.get_mut_ptr(),
    )
  };
  if FALSE == res {
    let last = std::io::Error::last_os_error();
    unsafe { SetupDiDestroyDeviceInfoList(adapter.DevInfo) };
    adapter.DevInfo = null_mut();
    return Err(error!(
      last,
      "Failed to open device instance ID {}",
      adapter.DevInstanceID.display()
    ));
  }
  if let Err(err) = PopulateAdapterData(&mut adapter) {
    return Err(error!(err, "Failed to populate adapter data"));
  }
  if let Err(err) = NciSetAdapterName(adapter.CfgInstanceID, &name) {
    return Err(error!(
      err,
      "Failed to set adapter name \"{}\"",
      name.display()
    ));
  }
  if system_params.IsWindows7 {
    create_adapter_post_win7(&mut adapter, &tunnel_type)
  }
  cleanupAdapter.forget();
  cleanupDriverInstall.run();
  dev_install_mutex.release();
  cleanup.run();
  Ok(adapter)
}
fn WintunCreateAdapterSwDevice(
  instance_id_str: &WideCStr,
  name: &WideCStr,
  tunnel_type: &WideCStr,
  root_node_name: &WideCStr,
  create_context: &mut SW_DEVICE_CREATE_CTX,
  adapter: &mut Adapter,
) -> std::io::Result<()> {
  let hwids = static_widecstr!("Wintun"; 8);
  let create_info = SW_DEVICE_CREATE_INFO {
    cbSize: csizeof!(SW_DEVICE_CREATE_INFO),
    pszInstanceId: instance_id_str.as_ptr(),
    pszzHardwareIds: hwids.as_ptr(),
    CapabilityFlags: (_SW_DEVICE_CAPABILITIES_SWDeviceCapabilitiesSilentInstall
      | _SW_DEVICE_CAPABILITIES_SWDeviceCapabilitiesDriverRequired) as _,
    pszDeviceDescription: tunnel_type.as_ptr(),
    ..unsafe { core::mem::zeroed() }
  };
  let device_properties = [
    DEVPROPERTY {
      CompKey: DEVPROPCOMPKEY {
        Key: DEVPKEY_Wintun_Name,
        Store: DEVPROP_STORE_SYSTEM,
        LocaleName: null_mut(),
      },
      Type: DEVPROP_TYPE_STRING,
      Buffer: unsafe { name.as_mut_ptr_bypass().cast() },
      BufferSize: name.sizeof(),
    },
    DEVPROPERTY {
      CompKey: DEVPROPCOMPKEY {
        Key: DEVPKEY_Device_FriendlyName,
        Store: DEVPROP_STORE_SYSTEM,
        LocaleName: null_mut(),
      },
      Type: DEVPROP_TYPE_STRING,
      Buffer: unsafe { tunnel_type.as_mut_ptr_bypass().cast() },
      BufferSize: tunnel_type.sizeof(),
    },
    DEVPROPERTY {
      CompKey: DEVPROPCOMPKEY {
        Key: DEVPKEY_Device_DeviceDesc,
        Store: DEVPROP_STORE_SYSTEM,
        LocaleName: null_mut(),
      },
      Type: DEVPROP_TYPE_STRING,
      Buffer: unsafe { tunnel_type.as_mut_ptr_bypass().cast() },
      BufferSize: tunnel_type.sizeof(),
    },
  ];
  let hret = unsafe {
    SwDeviceCreate(
      WINTUN_HWID.as_ptr(),
      root_node_name.as_ptr(),
      create_info.get_const_ptr(),
      device_properties.len() as u32,
      device_properties.as_ptr(),
      Some(DeviceCreateCallback),
      create_context.get_mut_ptr().cast(),
      adapter.SwDevice.get_mut_ptr(),
    )
  };
  if FAILED(hret) {
    return Err(error!(hret, "Failed to initiate device creation"));
  }
  let res = unsafe { WaitForSingleObject(create_context.Triggered, INFINITE) };
  if res != WAIT_OBJECT_0 {
    return Err(last_error!("Failed to wait for device creation trigger"));
  }
  if FAILED(create_context.CreateResult) {
    return Err(error!(
      create_context.CreateResult,
      "Failed to create device"
    ));
  }
  if let Err(err) = WaitForInterface(&adapter.DevInstanceID) {
    adapter.DevInfo =
      unsafe { SetupDiCreateDeviceInfoListExW(null_mut(), null_mut(), null_mut(), null_mut()) };
    if !check_handle(adapter.DevInfo) {
      adapter.DevInfo = null_mut();
      return Err(err);
    }
    adapter.DevInfoData.cbSize = csizeof!(=adapter.DevInfoData);
    let res = unsafe {
      SetupDiOpenDeviceInfoW(
        adapter.DevInfo,
        adapter.DevInstanceID.as_ptr(),
        null_mut(),
        DIOD_INHERIT_CLASSDRVS,
        adapter.DevInfoData.get_mut_ptr(),
      )
    };
    if FALSE == res {
      unsafe { SetupDiDestroyDeviceInfoList(adapter.DevInfo) };
      adapter.DevInfo = null_mut();
      return Err(err);
    }
    let mut property_type: DEVPROPTYPE = 0;
    let mut nt_status: NTSTATUS = 0;
    let res = unsafe {
      SetupDiGetDevicePropertyW(
        adapter.DevInfo,
        adapter.DevInfoData.get_mut_ptr(),
        DEVPKEY_Device_ProblemStatus.get_const_ptr(),
        property_type.get_mut_ptr(),
        nt_status.get_mut_ptr().cast(),
        csizeof!(=nt_status),
        null_mut(),
        0,
      )
    };
    if FALSE == res || property_type != DEVPROP_TYPE_NTSTATUS {
      nt_status = 0;
    }
    let mut problem_code: INT32 = 0;
    let res = unsafe {
      SetupDiGetDevicePropertyW(
        adapter.DevInfo,
        adapter.DevInfoData.get_mut_ptr(),
        DEVPKEY_Device_ProblemCode.get_const_ptr(),
        property_type.get_mut_ptr(),
        problem_code.get_mut_ptr().cast(),
        csizeof!(=problem_code),
        null_mut(),
        0,
      )
    };
    if FALSE == res || (property_type != DEVPROP_TYPE_INT32 && property_type != DEVPROP_TYPE_UINT32)
    {
      problem_code = 0;
    }
    let mut last = unsafe { RtlNtStatusToDosError(nt_status) };
    if last == ERROR_SUCCESS {
      last = ERROR_DEVICE_NOT_AVAILABLE;
    }
    return Err(error!(
      last,
      "Failed to setup adapter (problem code: 0x{:X}, ntstatus: 0x{:X})", problem_code, nt_status
    ));
  }
  Ok(())
}
fn WintunCreateAdapterStub(
  instance_id: GUID,
  instance_id_str: &WideCStr,
  tunnel_type: &WideCStr,
  root_node_name: &WideCStr,
  create_context: &mut SW_DEVICE_CREATE_CTX,
  adapter: &mut Adapter,
) -> std::io::Result<()> {
  let stub_create_info = SW_DEVICE_CREATE_INFO {
    cbSize: csizeof!(SW_DEVICE_CREATE_INFO),
    pszInstanceId: instance_id_str.as_ptr(),
    pszzHardwareIds: widecstr!("").as_ptr(),
    CapabilityFlags: (_SW_DEVICE_CAPABILITIES_SWDeviceCapabilitiesSilentInstall
      | _SW_DEVICE_CAPABILITIES_SWDeviceCapabilitiesDriverRequired) as u32,
    pszDeviceDescription: tunnel_type.as_ptr(),
    ..unsafe { std::mem::zeroed() }
  };
  let mut guid_devclass_net = GUID_DEVCLASS_NET;
  let stub_device_properties = [DEVPROPERTY {
    CompKey: DEVPROPCOMPKEY {
      Key: DEVPKEY_Device_ClassGuid,
      Store: DEVPROP_STORE_SYSTEM,
      ..unsafe { core::mem::zeroed() }
    },
    Type: DEVPROP_TYPE_GUID,
    Buffer: guid_devclass_net.get_mut_ptr().cast(),
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
      create_context.get_mut_ptr().cast(),
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
      create_context.CreateResult,
      "Failed to create stub device"
    ));
  }
  let mut dev_inst: DEVINST = 0;
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
  let mut driver_key: HKEY = null_mut();
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
  if cret != CR_SUCCESS {
    return Err(error!(
      Win32Error::from_cr(cret, ERROR_PNP_REGISTRY_ERROR),
      "Failed to create software registry key"
    ));
  }
  let driver_key = RegKey::from_raw(driver_key);
  let res = unsafe {
    RegSetValueExW(
      driver_key.as_raw(),
      widecstr!("SuggestedInstanceId").as_ptr(),
      0,
      REG_BINARY,
      instance_id.get_const_ptr().cast(),
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
  adapter.SwDevice = null_mut();
  Ok(())
}
pub fn WintunOpenAdapter(Name: &WideCStr) -> std::io::Result<Adapter> {
  unsafe { get_system_params() };
  unsafe_defer! { cleanup <-
    QueueUpOrphanedDeviceCleanupRoutine();
  };
  let dev_install_mutex = match SystemNamedMutexLock::take_device_installation_mutex() {
    Ok(res) => res,
    Err(err) => return Err(error!(err, "Failed to take device installation mutex")), // cleanup
  };
  let mut adapter = Adapter {
    InterfaceFilename: Default::default(),
    DevInstanceID: Default::default(),
    SwDevice: null_mut(),
    DevInfo: null_mut(),
    DevInfoData: unsafe { std::mem::zeroed() },
    CfgInstanceID: unsafe { std::mem::zeroed() },
    LuidIndex: 0,
    IfType: 0,
    IfIndex: 0,
  };
  info!("Opening adapter: {}", Name.display());
  let adapter_ptr = adapter.get_mut_ptr();
  unsafe_defer! { cleanupAdapter <-
    WintunCloseAdapter(&mut *adapter_ptr)
  };
  let DevInfo: HDEVINFO = unsafe {
    SetupDiGetClassDevsExW(
      &GUID_DEVCLASS_NET,
      WINTUN_ENUMERATOR!().as_ptr(),
      null_mut(),
      DIGCF_PRESENT,
      null_mut(),
      null_mut(),
      null_mut(),
    )
  };
  if !check_handle(DevInfo) {
    return Err(last_error!("Failed to get present adapters"));
    // goto cleanupAdapter
  }
  unsafe_defer! { cleanupDevInfo <-
    SetupDiDestroyDeviceInfoList(DevInfo);
  };

  let mut DevInfoData = SP_DEVINFO_DATA {
    cbSize: csizeof!(SP_DEVINFO_DATA),
    ..unsafe { std::mem::zeroed() }
  };
  let mut Found = false;
  for EnumIndex in 0.. {
    if FALSE == unsafe { SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &mut DevInfoData) } {
      if Win32Error::get_last_error().code() == ERROR_NO_MORE_ITEMS {
        break;
      }
      continue;
    }

    let mut PropType: DEVPROPTYPE = 0;
    let mut OtherName = StaticWideCStr::<MAX_ADAPTER_NAME>::zeroed();
    Found = TRUE
      == unsafe {
        SetupDiGetDevicePropertyW(
          DevInfo,
          &mut DevInfoData,
          &DEVPKEY_Wintun_Name,
          &mut PropType,
          OtherName.get_mut_ptr().cast(),
          OtherName.capacity(),
          null_mut(),
          0,
        )
      }
      && PropType == DEVPROP_TYPE_STRING
      && Name == OtherName.as_ref();
    if Found {
      break;
    }
  }
  if !Found {
    return Err(error!(
      ERROR_NOT_FOUND,
      "Failed to find matching adapter name"
    ));
    //goto cleanupDevInfo;
  }
  let mut RequiredChars: DWORD = adapter.DevInstanceID.capacity();
  if FALSE
    == unsafe {
      SetupDiGetDeviceInstanceIdW(
        DevInfo,
        &mut DevInfoData,
        adapter.DevInstanceID.as_mut_ptr(),
        RequiredChars,
        &mut RequiredChars,
      )
    }
  {
    return Err(last_error!("Failed to get adapter instance ID"));
    // goto cleanupDevInfo;
  }
  adapter.DevInfo = DevInfo;
  adapter.DevInfoData = DevInfoData;
  let Ret =
    WaitForInterface(&adapter.DevInstanceID).is_ok() && PopulateAdapterData(&mut adapter).is_ok();
  adapter.DevInfo = null_mut();
  if !Ret {
    return Err(last_error!("Failed to populate adapter"));
    // goto cleanupDevInfo;
  }
  cleanupDevInfo.run();
  cleanupAdapter.forget();
  dev_install_mutex.release();
  cleanup.run();
  Ok(adapter)
}

pub fn WintunCloseAdapter(Adapter: &mut Adapter) {
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

pub fn WintunGetAdapterLUID(Adapter: &Adapter) -> NET_LUID {
  let mut luid: NET_LUID = unsafe { std::mem::zeroed() };
  luid.set_NetLuidIndex(Adapter.LuidIndex as u64);
  luid.set_IfType(Adapter.IfType as u64);
  luid
}

pub(crate) fn AdapterOpenDeviceObject(Adapter: &Adapter) -> std::io::Result<HANDLE> {
  let handle = unsafe {
    CreateFileW(
      Adapter.InterfaceFilename.as_ptr(),
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      null_mut(),
      OPEN_EXISTING,
      0,
      null_mut(),
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
  let mut guid_devinterface_net = GUID_DEVINTERFACE_NET;
  let cr = unsafe {
    CM_Get_Device_Interface_List_SizeW(
      interface_len.get_mut_ptr(),
      guid_devinterface_net.get_mut_ptr(),
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
      guid_devinterface_net.get_mut_ptr(),
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
    let Event = unsafe { CreateEventW(null_mut(), FALSE, FALSE, std::ptr::null()) };
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
  _DevQuery: HDEVQUERY,
  Context: PVOID,
  ActionData: *const DEV_QUERY_RESULT_ACTION_DATA,
) {
  let Ctx = &mut *(Context as *mut WAIT_FOR_INTERFACE_CTX);
  let ActionData = &*ActionData;
  let mut Ret = ERROR_SUCCESS;
  match ActionData.Action {
    _DEV_QUERY_RESULT_ACTION_DevQueryResultStateChange => {
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
  let system_params = unsafe { get_system_params() };
  if system_params.IsWindows7 {
    return Ok(());
  }
  let sizeof_InstanceId: DWORD = InstanceId.sizeof();
  let InstanceIdPtr = unsafe { InstanceId.as_mut_ptr_bypass() };
  let mut devprop_true = DEVPROP_TRUE;
  let mut guid_devinterface_net = GUID_DEVINTERFACE_NET;
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
        Buffer: devprop_true.get_mut_ptr().cast(),
        BufferSize: csizeof!(=devprop_true),
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
        Buffer: guid_devinterface_net.get_mut_ptr().cast(),
        BufferSize: csizeof!(=guid_devinterface_net),
      },
    },
  ];
  let mut Ctx = WAIT_FOR_INTERFACE_CTX::new()?;
  let mut Query: HDEVQUERY = null_mut();
  let HRet = unsafe {
    DevCreateObjectQuery(
      _DEV_OBJECT_TYPE_DevObjectTypeDeviceInterface,
      _DEV_QUERY_FLAGS_DevQueryFlagUpdateResults as _,
      0,
      std::ptr::null(),
      Filters.len() as DWORD,
      Filters.as_ptr(),
      Some(WaitForInterfaceCallback),
      Ctx.get_mut_ptr().cast(),
      Query.get_mut_ptr(),
    )
  };
  if FAILED(HRet) {
    return Err(error!(HRet, "Failed to create device query"));
  }
  defer! { cleanupQuery <-
    unsafe { DevCloseObjectQuery(Query) }
  };
  let result = unsafe { WaitForSingleObject(Ctx.Event, 15000) };
  if result != WAIT_OBJECT_0 {
    if result == WAIT_FAILED {
      return Err(last_error!("Failed to wait for device query"));
    }
    return Err(error!(result, "Timed out waiting for device query"));
  }
  if Ctx.LastError != ERROR_SUCCESS {
    return Err(error!(Ctx.LastError, "Failed to get enabled device"));
  }
  cleanupQuery.run();
  Ok(())
}

#[derive(Debug)]
#[repr(C)]
pub(crate) struct SW_DEVICE_CREATE_CTX {
  CreateResult: HRESULT,
  DeviceInstanceId: *mut StaticWideCStr<MAX_DEVICE_ID_LEN>,
  Triggered: HANDLE,
}

impl SW_DEVICE_CREATE_CTX {
  pub fn new(id: &mut StaticWideCStr<MAX_DEVICE_ID_LEN>) -> std::io::Result<Self> {
    let Triggered = unsafe { CreateEventW(null_mut(), FALSE, FALSE, std::ptr::null()) };
    if !check_handle(Triggered) {
      return Err(last_error!("Failed to create event"));
    }
    Ok(Self {
      CreateResult: 0,
      DeviceInstanceId: id.get_mut_ptr(),
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
  _SwDevice: HSWDEVICE,
  CreateResult: HRESULT,
  Context: PVOID,
  DeviceInstanceId: PCWSTR,
) {
  let Ctx = &mut *(Context as *mut SW_DEVICE_CREATE_CTX);
  Ctx.CreateResult = CreateResult;
  if !DeviceInstanceId.is_null() {
    *Ctx.DeviceInstanceId =
      StaticWideCStr::<MAX_DEVICE_ID_LEN>::from_ptr_unchecked(DeviceInstanceId, MAX_DEVICE_ID_LEN);
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

fn PopulateAdapterData(Adapter: &mut Adapter) -> std::io::Result<()> {
  let Key = RegKey::open(
    Adapter.DevInfo,
    Adapter.DevInfoData.get_mut_ptr(),
    DICS_FLAG_GLOBAL,
    0,
    DIREG_DRV,
    KEY_QUERY_VALUE,
  )?;

  let value_str = RegistryQueryString(&Key, widecstr!("NetCfgInstanceId"), true)?;
  let result = unsafe { CLSIDFromString(value_str.as_ptr(), Adapter.CfgInstanceID.get_mut_ptr()) };
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
  Key.close();
  Ok(())
}

unsafe extern "system" fn DoOrphanedDeviceCleanup(_Ctx: LPVOID) -> DWORD {
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
    unsafe { QueueUserWorkItem(Some(DoOrphanedDeviceCleanup), null_mut(), 0) };
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
      null_mut(),
      0,
      null_mut(),
      null_mut(),
      null_mut(),
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
        null_mut(),
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
      WINTUN_ENUMERATOR!().as_ptr(),
      null_mut(),
      0,
      null_mut(),
      null_mut(),
      null_mut(),
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
  let avaliable_name = Name.to_owned();
  for _i in 0..MAX_SUFFIX {
    match SetConnectionName(Guid, avaliable_name.as_ref()) {
      Ok(()) => return Ok(avaliable_name),
      Err(err) if err.raw_os_error().unwrap() == ERROR_DUP_NAME as i32 => {}
      Err(err) => return Err(err),
    };
    todo!("Trying another name is not implemented")
  }
  Err(std::io::Error::from_raw_os_error(ERROR_DUP_NAME as i32))
}
