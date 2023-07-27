use std::ptr::null_mut;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use cutils::errors::get_last_error_code;
use cutils::ignore::ResultIgnoreExt;
use cutils::inspection::GetPtrExt;
use cutils::strings::{StaticWideCStr, WideCStr, WideCString};
use cutils::{
  check_handle, csizeof, defer, guid_eq, static_widecstr, unsafe_defer, widecstr, ErrorFromCrExt,
};
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

use crate::adapter_win7::{
  cleanup_orphaned_devices_win7, create_adapter_post_win7, create_adapter_win7,
};
use crate::driver::{driver_install, driver_install_deferred_cleanup};
use crate::logger::logger_get_registry_key_path;
use crate::logger::{error, info, last_error, log};
use crate::namespace::SystemNamedMutexLock;
use crate::nci::set_connection_name;
use crate::registry::{RegKey, registry_query_dword, registry_query_string};
use crate::rundll32::*;
use crate::session::{ConstrunctsAndProvidesSession, Session, wintun_start_session};
use crate::winapi_ext::devquery::{
  DevCloseObjectQuery, DevCreateObjectQuery, DEVPROP_FILTER_EXPRESSION,
  DEVPROP_OPERATOR::{EQUALS, EQUALS_IGNORE_CASE},
  DEV_OBJECT_TYPE, DEV_QUERY_FLAGS, DEV_QUERY_RESULT_ACTION, DEV_QUERY_RESULT_ACTION_DATA,
  DEV_QUERY_STATE, HDEVQUERY,
};
use crate::winapi_ext::swdevice::{
  DriverRequired, SilentInstall, SwDeviceClose, SwDeviceCreate, HSWDEVICE, SW_DEVICE_CREATE_INFO,
};
use crate::winapi_ext::winternl::RtlNtStatusToDosError;
use crate::wmain::{get_system_params, IMAGE_FILE_PROCESS};
use crate::{IpAndMaskPrefix, RingCapacity};

pub(crate) const WINTUN_HWID: &WideCStr = widecstr!("Wintun");
macro_rules! WINTUN_ENUMERATOR {
  () => {
    if unsafe { $crate::wmain::get_system_params() }.is_windows7 {
      widecstr!(r"ROOT\Wintun")
    } else {
      widecstr!(r"SWD\Wintun")
    }
  };
}
pub(crate) use WINTUN_ENUMERATOR;

pub(crate) const DEVPKEY_WINTUN_NAME: DEVPROPKEY = DEVPROPKEY {
  fmtid: DEVPROPGUID {
    Data1: 0x3361c968,
    Data2: 0x2f2e,
    Data3: 0x4660,
    Data4: [0xb4, 0x7e, 0x69, 0x9c, 0xdc, 0x4c, 0x32, 0xb9],
  },
  pid: DEVPROPID_FIRST_USABLE + 1,
};

static ORPHAN_THREAD_IS_WORKING: AtomicBool = AtomicBool::new(false);

pub struct Adapter {
  pub(crate) sw_device: HSWDEVICE,
  pub(crate) dev_info: HDEVINFO,
  pub(crate) dev_info_data: SP_DEVINFO_DATA,
  pub(crate) interface_filename: WideCString,
  pub(crate) cfg_instance_id: GUID,
  pub(crate) dev_instance_id: StaticWideCStr<MAX_DEVICE_ID_LEN>,
  pub(crate) luid_index: DWORD,
  pub(crate) if_type: DWORD,
  #[allow(dead_code)]
  pub(crate) if_index: DWORD,
}

unsafe impl Sync for Adapter {}
unsafe impl Send for Adapter {}

pub trait ConstructsAndProvidesAdapter {
  type MutRef<'a>: std::ops::DerefMut<Target = Adapter>
  where
    Self: 'a;
  fn construct(adapter: Adapter) -> Self;
  fn provide<'a, 'this>(&'this mut self) -> Self::MutRef<'a>
  where
    'this: 'a;
}

impl ConstructsAndProvidesAdapter for Box<Adapter> {
  type MutRef<'a> = &'a mut Adapter;
  fn construct(adapter: Adapter) -> Self {
    Box::new(adapter)
  }

  fn provide<'a, 'this>(&'this mut self) -> Self::MutRef<'a>
  where
    'this: 'a,
  {
    &mut *self
  }
}

impl ConstructsAndProvidesAdapter for Arc<Mutex<Adapter>> {
  type MutRef<'a> = std::sync::MutexGuard<'a, Adapter>;
  fn construct(adapter: Adapter) -> Self {
    Arc::new(Mutex::new(adapter))
  }

  fn provide<'a, 'this>(&'this mut self) -> Self::MutRef<'a>
  where
    'this: 'a,
  {
    self.lock().unwrap()
  }
}

impl ConstructsAndProvidesAdapter for std::rc::Rc<std::cell::RefCell<Adapter>> {
  type MutRef<'a> = std::cell::RefMut<'a, Adapter>;
  fn construct(adapter: Adapter) -> Self {
    std::rc::Rc::new(std::cell::RefCell::new(adapter))
  }

  fn provide<'a, 'this>(&'this mut self) -> Self::MutRef<'a>
  where
    'this: 'a,
  {
    self.try_borrow_mut().unwrap()
  }
}

impl Adapter {
  pub fn create(
    name: &str,
    tunnel_type: &str,
    requested_guid: Option<GUID>,
  ) -> std::io::Result<Box<Adapter>> {
    let name: StaticWideCStr<MAX_ADAPTER_NAME> = cutils::strings::encode(name).ok_or(
      std::io::Error::new(std::io::ErrorKind::InvalidInput, "Tunnel name is too long"),
    )?;
    let tunnel_type: StaticWideCStr<MAX_ADAPTER_NAME> = cutils::strings::encode(tunnel_type)
      .ok_or(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "Tunnel type is too long",
      ))?;
    wintun_create_adapter(&name, &tunnel_type, requested_guid)
  }
  pub fn create_wrapped<T: ConstructsAndProvidesAdapter>(
    name: &str,
    tunnel_type: &str,
    requested_guid: Option<GUID>,
  ) -> std::io::Result<T> {
    let name: StaticWideCStr<MAX_ADAPTER_NAME> = cutils::strings::encode(name).ok_or(
      std::io::Error::new(std::io::ErrorKind::InvalidInput, "Tunnel name is too long"),
    )?;
    let tunnel_type: StaticWideCStr<MAX_ADAPTER_NAME> = cutils::strings::encode(tunnel_type)
      .ok_or(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "Tunnel type is too long",
      ))?;
    wintun_create_adapter(&name, &tunnel_type, requested_guid)
  }
  pub fn open(name: &str) -> std::io::Result<Box<Adapter>> {
    let name: StaticWideCStr<MAX_ADAPTER_NAME> = cutils::strings::encode(name).ok_or(
      std::io::Error::new(std::io::ErrorKind::InvalidInput, "Tunnel name is too long"),
    )?;
    wintun_open_adapter(&name)
  }
  pub fn open_wrapped<T: ConstructsAndProvidesAdapter>(name: &str) -> std::io::Result<T> {
    let name: StaticWideCStr<MAX_ADAPTER_NAME> = cutils::strings::encode(name).ok_or(
      std::io::Error::new(std::io::ErrorKind::InvalidInput, "Tunnel name is too long"),
    )?;
    wintun_open_adapter(&name)
  }
  pub fn close(self: Box<Adapter>) {
    drop(self)
  }
  pub fn get_luid(&self) -> NET_LUID {
    wintun_get_adapter_luid(self)
  }
  pub fn get_guid(&self) -> GUID {
    self.cfg_instance_id
  }
  pub fn start_session(&mut self, capacity: RingCapacity) -> std::io::Result<Box<Session>> {
    wintun_start_session(self, capacity.0)
  }
  pub fn start_session_wrapped<T: ConstrunctsAndProvidesSession>(
    &mut self,
    capacity: RingCapacity,
  ) -> std::io::Result<T> {
    wintun_start_session(self, capacity.0)
  }
  pub fn set_ip_address(&mut self, internal_ip: IpAndMaskPrefix) -> std::io::Result<()> {
    let mut address_row = winapi::shared::netioapi::MIB_UNICASTIPADDRESS_ROW::default();
    unsafe {
      winapi::shared::netioapi::InitializeUnicastIpAddressEntry(&mut address_row as *mut _);
    }
    const IP_SUFFIX_ORIGIN_DHCP: winapi::shared::nldef::NL_SUFFIX_ORIGIN = 3;
    const IP_PREFIX_ORIGIN_DHCP: winapi::shared::nldef::NL_PREFIX_ORIGIN = 3;
    address_row.SuffixOrigin = IP_SUFFIX_ORIGIN_DHCP;
    address_row.PrefixOrigin = IP_PREFIX_ORIGIN_DHCP;
    const LIFETIME_INFINITE: winapi::ctypes::c_ulong = 0xffffffff;
    address_row.ValidLifetime = LIFETIME_INFINITE;
    address_row.PreferredLifetime = LIFETIME_INFINITE;
    address_row.InterfaceLuid = winapi::shared::ifdef::NET_LUID_LH {
      Value: self.get_luid().Value,
    };
    match internal_ip {
      IpAndMaskPrefix::V4 { ip, prefix } => {
        unsafe {
          let ipv4 = address_row.Address.Ipv4_mut();
          ipv4.sin_family = winapi::shared::ws2def::AF_INET as _;
          *ipv4.sin_addr.S_un.S_addr_mut() = u32::from_ne_bytes(ip.octets());
        }
        address_row.OnLinkPrefixLength = prefix.mask();
      }
      IpAndMaskPrefix::V6 { ip, prefix } => {
        unsafe {
          let ipv6 = address_row.Address.Ipv6_mut();
          ipv6.sin6_family = winapi::shared::ws2def::AF_INET6 as _;
          *ipv6.sin6_addr.u.Byte_mut() = ip.octets();
        }
        address_row.OnLinkPrefixLength = prefix.mask();
      }
    }

    address_row.DadState = winapi::shared::nldef::IpDadStatePreferred;
    let error =
      unsafe { winapi::shared::netioapi::CreateUnicastIpAddressEntry(&mut address_row as *mut _) };
    if error != NO_ERROR {
      return Err(std::io::Error::from_raw_os_error(error as i32));
    }
    Ok(())
  }
}

impl Drop for Adapter {
  fn drop(&mut self) {
    wintun_close_adapter(self)
  }
}

pub fn wintun_create_adapter<T: ConstructsAndProvidesAdapter>(
  name: &StaticWideCStr<MAX_ADAPTER_NAME>,
  tunnel_type: &StaticWideCStr<MAX_ADAPTER_NAME>,
  requested_guid: Option<GUID>,
) -> std::io::Result<T> {
  let _system_params = unsafe { get_system_params() };
  unsafe_defer! { cleanup <-
    queue_up_orphaned_device_cleanup_routine();
  };
  let dev_install_mutex = match SystemNamedMutexLock::take_device_installation_mutex() {
    Ok(res) => res,
    Err(err) => return Err(error!(err, "Failed to take device installation mutex")), // cleanup
  };
  let (dev_info_existing_adapters, mut existing_adapters) = driver_install()?; // cleanupDeviceInstallationMutex
  info!("Creating adapter");
  let mut adapter = T::construct(Adapter {
    interface_filename: Default::default(),
    dev_instance_id: Default::default(),
    sw_device: null_mut(),
    dev_info: null_mut(),
    dev_info_data: unsafe { std::mem::zeroed() },
    cfg_instance_id: unsafe { std::mem::zeroed() },
    luid_index: 0,
    if_type: 0,
    if_index: 0,
  });
  unsafe_defer! { cleanup_driver_install <-
    driver_install_deferred_cleanup(dev_info_existing_adapters, &mut existing_adapters);
  };
  let mut adapter_prov = adapter.provide();
  let adapter_ptr = (*adapter_prov).get_mut_ptr();
  unsafe_defer! { cleanup_adapter <-
    wintun_close_adapter(&mut *adapter_ptr)
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
      std::io::Error::from_cr(result, ERROR_GEN_FAILURE),
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
      std::io::Error::from_cr(result, ERROR_GEN_FAILURE),
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

  let mut create_context = SwDeviceCreateCtx::new(&mut adapter_prov.dev_instance_id)?;
  let system_params = unsafe { get_system_params() };
  if system_params.is_windows7 {
    create_adapter_win7(&mut adapter_prov, &name, &tunnel_type)?;
    // goto skipSwDevice
  } else {
    if system_params.is_windows10 {
      wintun_create_adapter_stub(
        instance_id,
        &instance_id_str,
        &tunnel_type,
        &root_node_name,
        &mut create_context,
        &mut adapter_prov,
      )?;
    }
    wintun_create_adapter_sw_device(
      &instance_id_str,
      &name,
      &tunnel_type,
      &root_node_name,
      &mut create_context,
      &mut adapter_prov,
    )?;
  }
  adapter_prov.dev_info = unsafe {
    SetupDiCreateDeviceInfoListExW(
      GUID_DEVCLASS_NET.get_const_ptr(),
      null_mut(),
      null_mut(),
      null_mut(),
    )
  };
  if !check_handle(adapter_prov.dev_info) {
    adapter_prov.dev_info = null_mut();
    return Err(last_error!("Failed to make device list"));
  }
  adapter_prov.dev_info_data.cbSize = csizeof!(=adapter_prov.dev_info_data);
  let res = unsafe {
    SetupDiOpenDeviceInfoW(
      adapter_prov.dev_info,
      adapter_prov.dev_instance_id.as_ptr(),
      null_mut(),
      DIOD_INHERIT_CLASSDRVS,
      adapter_prov.dev_info_data.get_mut_ptr(),
    )
  };
  if FALSE == res {
    let last = std::io::Error::last_os_error();
    unsafe { SetupDiDestroyDeviceInfoList(adapter_prov.dev_info) };
    adapter_prov.dev_info = null_mut();
    return Err(error!(
      last,
      "Failed to open device instance ID {}",
      adapter_prov.dev_instance_id.display()
    ));
  }
  if let Err(err) = populate_adapter_data(&mut adapter_prov) {
    return Err(error!(err, "Failed to populate adapter data"));
  }
  if let Err(err) = nci_set_adapter_name(adapter_prov.cfg_instance_id, &name) {
    return Err(error!(
      err,
      "Failed to set adapter name \"{}\"",
      name.display()
    ));
  }
  if system_params.is_windows7 {
    create_adapter_post_win7(&mut adapter_prov, &tunnel_type)
  }
  drop(adapter_prov);
  cleanup_adapter.forget();
  cleanup_driver_install.run();
  dev_install_mutex.release();
  cleanup.run();
  Ok(adapter)
}

fn wintun_create_adapter_sw_device(
  instance_id_str: &WideCStr,
  name: &WideCStr,
  tunnel_type: &WideCStr,
  root_node_name: &WideCStr,
  create_context: &mut SwDeviceCreateCtx,
  adapter: &mut Adapter,
) -> std::io::Result<()> {
  let hwids = static_widecstr!("Wintun"; 8);
  let create_info = SW_DEVICE_CREATE_INFO {
    cbSize: csizeof!(SW_DEVICE_CREATE_INFO),
    pszInstanceId: instance_id_str.as_ptr(),
    pszzHardwareIds: hwids.as_ptr(),
    CapabilityFlags: SilentInstall | DriverRequired,
    pszDeviceDescription: tunnel_type.as_ptr(),
    ..unsafe { core::mem::zeroed() }
  };
  let device_properties = [
    DEVPROPERTY {
      CompKey: DEVPROPCOMPKEY {
        Key: DEVPKEY_WINTUN_NAME,
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
      Some(device_create_callback),
      create_context.get_mut_ptr().cast(),
      adapter.sw_device.get_mut_ptr(),
    )
  };
  if FAILED(hret) {
    return Err(error!(hret, "Failed to initiate device creation"));
  }
  let res = unsafe { WaitForSingleObject(create_context.triggered, INFINITE) };
  if res != WAIT_OBJECT_0 {
    return Err(last_error!("Failed to wait for device creation trigger"));
  }
  if FAILED(create_context.create_result) {
    return Err(error!(
      create_context.create_result,
      "Failed to create device"
    ));
  }
  if let Err(err) = wait_for_interface(&adapter.dev_instance_id) {
    adapter.dev_info =
      unsafe { SetupDiCreateDeviceInfoListExW(null_mut(), null_mut(), null_mut(), null_mut()) };
    if !check_handle(adapter.dev_info) {
      adapter.dev_info = null_mut();
      return Err(err);
    }
    adapter.dev_info_data.cbSize = csizeof!(=adapter.dev_info_data);
    let res = unsafe {
      SetupDiOpenDeviceInfoW(
        adapter.dev_info,
        adapter.dev_instance_id.as_ptr(),
        null_mut(),
        DIOD_INHERIT_CLASSDRVS,
        adapter.dev_info_data.get_mut_ptr(),
      )
    };
    if FALSE == res {
      unsafe { SetupDiDestroyDeviceInfoList(adapter.dev_info) };
      adapter.dev_info = null_mut();
      return Err(err);
    }
    let mut property_type: DEVPROPTYPE = 0;
    let mut nt_status: NTSTATUS = 0;
    let res = unsafe {
      SetupDiGetDevicePropertyW(
        adapter.dev_info,
        adapter.dev_info_data.get_mut_ptr(),
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
        adapter.dev_info,
        adapter.dev_info_data.get_mut_ptr(),
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
fn wintun_create_adapter_stub(
  instance_id: GUID,
  instance_id_str: &WideCStr,
  tunnel_type: &WideCStr,
  root_node_name: &WideCStr,
  create_context: &mut SwDeviceCreateCtx,
  adapter: &mut Adapter,
) -> std::io::Result<()> {
  let stub_create_info = SW_DEVICE_CREATE_INFO {
    cbSize: csizeof!(SW_DEVICE_CREATE_INFO),
    pszInstanceId: instance_id_str.as_ptr(),
    pszzHardwareIds: widecstr!("").as_ptr(),
    CapabilityFlags: (SilentInstall | DriverRequired) as u32,
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
      Some(device_create_callback),
      create_context.get_mut_ptr().cast(),
      adapter.sw_device.get_mut_ptr(),
    )
  };
  if FAILED(hret) {
    return Err(error!(hret, "Failed to initiate stub device creation"));
  }
  let res = unsafe { WaitForSingleObject(create_context.triggered, INFINITE) };
  if res != WAIT_OBJECT_0 {
    return Err(last_error!(
      "Failed to wait for stub device creation trigger"
    ));
  }
  if FAILED(create_context.create_result) {
    return Err(error!(
      create_context.create_result,
      "Failed to create stub device"
    ));
  }
  let mut dev_inst: DEVINST = 0;
  let cret = unsafe {
    CM_Locate_DevNodeW(
      dev_inst.get_mut_ptr(),
      adapter.dev_instance_id.as_mut_ptr(),
      CM_LOCATE_DEVINST_PHANTOM,
    )
  };
  if cret != CR_SUCCESS {
    return Err(error!(
      std::io::Error::from_cr(cret, ERROR_DEVICE_ENUMERATION_ERROR),
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
      std::io::Error::from_cr(cret, ERROR_PNP_REGISTRY_ERROR),
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
    SwDeviceClose(adapter.sw_device);
  }
  adapter.sw_device = null_mut();
  Ok(())
}
pub fn wintun_open_adapter<T: ConstructsAndProvidesAdapter>(name: &WideCStr) -> std::io::Result<T> {
  unsafe { get_system_params() };
  unsafe_defer! { cleanup <-
    queue_up_orphaned_device_cleanup_routine();
  };
  let dev_install_mutex = match SystemNamedMutexLock::take_device_installation_mutex() {
    Ok(res) => res,
    Err(err) => return Err(error!(err, "Failed to take device installation mutex")), // cleanup
  };
  let mut adapter = T::construct(Adapter {
    interface_filename: Default::default(),
    dev_instance_id: Default::default(),
    sw_device: null_mut(),
    dev_info: null_mut(),
    dev_info_data: unsafe { std::mem::zeroed() },
    cfg_instance_id: unsafe { std::mem::zeroed() },
    luid_index: 0,
    if_type: 0,
    if_index: 0,
  });
  info!("Opening adapter: {}", name.display());
  let mut adapter_prov = adapter.provide();
  let adapter_ptr = (*adapter_prov).get_mut_ptr();
  unsafe_defer! { cleanup_adapter <-
    wintun_close_adapter(&mut *adapter_ptr)
  };
  let dev_info: HDEVINFO = unsafe {
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
  if !check_handle(dev_info) {
    return Err(last_error!("Failed to get present adapters"));
    // goto cleanupAdapter
  }
  unsafe_defer! { cleanup_dev_info <-
    SetupDiDestroyDeviceInfoList(dev_info);
  };

  let mut dev_info_data = SP_DEVINFO_DATA {
    cbSize: csizeof!(SP_DEVINFO_DATA),
    ..unsafe { std::mem::zeroed() }
  };
  let mut found = false;
  for enum_index in 0.. {
    if FALSE == unsafe { SetupDiEnumDeviceInfo(dev_info, enum_index, &mut dev_info_data) } {
      if get_last_error_code() == ERROR_NO_MORE_ITEMS {
        break;
      }
      continue;
    }

    let mut prop_type: DEVPROPTYPE = 0;
    let mut other_name = StaticWideCStr::<MAX_ADAPTER_NAME>::zeroed();
    found = TRUE
      == unsafe {
        SetupDiGetDevicePropertyW(
          dev_info,
          &mut dev_info_data,
          &DEVPKEY_WINTUN_NAME,
          &mut prop_type,
          other_name.get_mut_ptr().cast(),
          other_name.capacity(),
          null_mut(),
          0,
        )
      }
      && prop_type == DEVPROP_TYPE_STRING
      && name == other_name.as_ref();
    if found {
      break;
    }
  }
  if !found {
    return Err(error!(
      ERROR_NOT_FOUND,
      "Failed to find matching adapter name"
    ));
    //goto cleanupDevInfo;
  }
  let mut required_chars: DWORD = adapter_prov.dev_instance_id.capacity();
  if FALSE
    == unsafe {
      SetupDiGetDeviceInstanceIdW(
        dev_info,
        &mut dev_info_data,
        adapter_prov.dev_instance_id.as_mut_ptr(),
        required_chars,
        &mut required_chars,
      )
    }
  {
    return Err(last_error!("Failed to get adapter instance ID"));
    // goto cleanupDevInfo;
  }
  adapter_prov.dev_info = dev_info;
  adapter_prov.dev_info_data = dev_info_data;
  let adapter_prov_ptr = adapter_prov.get_mut_ptr();
  unsafe_defer! { set_dev_info_to_null <-
    last_error!("Failed to populate adapter");
    (*adapter_prov_ptr).dev_info = null_mut();
  };
  wait_for_interface(&adapter_prov.dev_instance_id)?;
  populate_adapter_data(&mut adapter_prov)?;
  set_dev_info_to_null.forget();
  cleanup_dev_info.run();
  cleanup_adapter.forget();
  dev_install_mutex.release();
  cleanup.run();
  drop(adapter_prov);
  Ok(adapter)
}

pub fn wintun_close_adapter(adapter: &mut Adapter) {
  if !adapter.sw_device.is_null() {
    unsafe { SwDeviceClose(adapter.sw_device) };
  }
  if !adapter.dev_info.is_null() {
    if let Err(err) = adapter_remove_instance(adapter.dev_info, adapter.dev_info_data.get_mut_ptr()) {
      error!(err, "Failed to remove adapter when closing");
    }
    unsafe { SetupDiDestroyDeviceInfoList(adapter.dev_info) };
  }
  // Free(Adapter.get_mut_ptr().cast_to_pvoid());
  queue_up_orphaned_device_cleanup_routine();
}

pub fn wintun_get_adapter_luid(adapter: &Adapter) -> NET_LUID {
  let mut luid: NET_LUID = unsafe { std::mem::zeroed() };
  luid.set_NetLuidIndex(adapter.luid_index as u64);
  luid.set_IfType(adapter.if_type as u64);
  luid
}

pub(crate) fn adapter_open_device_object(adapter: &Adapter) -> std::io::Result<HANDLE> {
  let handle = unsafe {
    CreateFileW(
      adapter.interface_filename.as_ptr(),
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
      adapter.interface_filename.display()
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

pub(crate) fn adapter_get_device_object_file_name(
  instance_id: &WideCStr,
) -> std::io::Result<WideCString> {
  let mut interface_len = 0;
  let mut guid_devinterface_net = GUID_DEVINTERFACE_NET;
  let cr = unsafe {
    CM_Get_Device_Interface_List_SizeW(
      interface_len.get_mut_ptr(),
      guid_devinterface_net.get_mut_ptr(),
      instance_id.as_ptr() as DEVINSTID_W,
      CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
    )
  };
  if cr != CR_SUCCESS {
    let err = std::io::Error::from_cr(cr, ERROR_GEN_FAILURE);
    let err = error!(
      err,
      "Failed to query adapter {} associated instances size",
      instance_id.display()
    );
    return Err(err);
  }
  let mut interfaces = vec![0 as WCHAR; interface_len as usize];
  let cr = unsafe {
    CM_Get_Device_Interface_ListW(
      guid_devinterface_net.get_mut_ptr(),
      instance_id.as_ptr() as DEVINSTID_W,
      interfaces.as_mut_ptr(),
      interface_len,
      CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
    )
  };
  if cr != CR_SUCCESS {
    let err = std::io::Error::from_cr(cr, ERROR_GEN_FAILURE);
    let err = error!(
      err,
      "Failed to get adapter {} associated instances",
      instance_id.display()
    );
    return Err(err);
  }
  Ok(WideCString::from(interfaces))
}

#[repr(C)]
pub(crate) struct WaitForInterfaceCtx {
  event: HANDLE,
  last_error: DWORD,
}

impl WaitForInterfaceCtx {
  pub fn new() -> std::io::Result<Self> {
    let event = unsafe { CreateEventW(null_mut(), FALSE, FALSE, std::ptr::null()) };
    if !check_handle(event) {
      return Err(last_error!("Failed to create event"));
    }
    Ok(Self {
      event,
      last_error: ERROR_SUCCESS,
    })
  }
}

impl Drop for WaitForInterfaceCtx {
  fn drop(&mut self) {
    unsafe { CloseHandle(self.event) };
  }
}

pub(crate) unsafe extern "system" fn wait_for_interface_callback(
  _dev_query: HDEVQUERY,
  context: PVOID,
  action_data: *const DEV_QUERY_RESULT_ACTION_DATA,
) {
  let ctx = &mut *(context as *mut WaitForInterfaceCtx);
  let action_data = &*action_data;
  let mut ret = ERROR_SUCCESS;
  match action_data.Action {
    DEV_QUERY_RESULT_ACTION::StateChange => {
      if action_data.Data.State != DEV_QUERY_STATE::Aborted {
        return;
      }
      ret = ERROR_DEVICE_NOT_AVAILABLE;
    }
    DEV_QUERY_RESULT_ACTION::Add | DEV_QUERY_RESULT_ACTION::Update => {}
    _ => return,
  }
  ctx.last_error = ret;
  SetEvent(ctx.event);
}

pub(crate) fn wait_for_interface(instance_id: &WideCStr) -> std::io::Result<()> {
  let system_params = unsafe { get_system_params() };
  if system_params.is_windows7 {
    return Ok(());
  }
  let sizeof_instance_id: DWORD = instance_id.sizeof();
  let instance_id_ptr = unsafe { instance_id.as_mut_ptr_bypass() };
  let mut devprop_true = DEVPROP_TRUE;
  let mut guid_devinterface_net = GUID_DEVINTERFACE_NET;
  let filters = [
    DEVPROP_FILTER_EXPRESSION {
      Operator: EQUALS_IGNORE_CASE,
      Property: DEVPROPERTY {
        CompKey: DEVPROPCOMPKEY {
          Key: DEVPKEY_Device_InstanceId,
          Store: DEVPROP_STORE_SYSTEM,
          LocaleName: null_mut(),
        },
        Type: DEVPROP_TYPE_STRING,
        Buffer: instance_id_ptr.cast(),
        BufferSize: sizeof_instance_id,
      },
    },
    DEVPROP_FILTER_EXPRESSION {
      Operator: EQUALS,
      Property: DEVPROPERTY {
        CompKey: DEVPROPCOMPKEY {
          Key: DEVPKEY_DeviceInterface_Enabled,
          Store: DEVPROP_STORE_SYSTEM,
          LocaleName: null_mut(),
        },
        Type: DEVPROP_TYPE_BOOLEAN,
        Buffer: devprop_true.get_mut_ptr().cast(),
        BufferSize: csizeof!(=devprop_true),
      },
    },
    DEVPROP_FILTER_EXPRESSION {
      Operator: EQUALS,
      Property: DEVPROPERTY {
        CompKey: DEVPROPCOMPKEY {
          Key: DEVPKEY_DeviceInterface_ClassGuid,
          Store: DEVPROP_STORE_SYSTEM,
          LocaleName: null_mut(),
        },
        Type: DEVPROP_TYPE_GUID,
        Buffer: guid_devinterface_net.get_mut_ptr().cast(),
        BufferSize: csizeof!(=guid_devinterface_net),
      },
    },
  ];
  let mut ctx = WaitForInterfaceCtx::new()?;
  let mut query: HDEVQUERY = null_mut();
  let hret = unsafe {
    DevCreateObjectQuery(
      DEV_OBJECT_TYPE::DeviceInterface,
      DEV_QUERY_FLAGS::UpdateResults as _,
      0,
      std::ptr::null(),
      filters.len() as DWORD,
      filters.as_ptr(),
      Some(wait_for_interface_callback),
      ctx.get_mut_ptr().cast(),
      query.get_mut_ptr(),
    )
  };
  if FAILED(hret) {
    return Err(error!(hret, "Failed to create device query"));
  }
  defer! { cleanup_query <-
    unsafe { DevCloseObjectQuery(query) }
  };
  let result = unsafe { WaitForSingleObject(ctx.event, 15000) };
  if result != WAIT_OBJECT_0 {
    if result == WAIT_FAILED {
      return Err(last_error!("Failed to wait for device query"));
    }
    return Err(error!(result, "Timed out waiting for device query"));
  }
  if ctx.last_error != ERROR_SUCCESS {
    return Err(error!(ctx.last_error, "Failed to get enabled device"));
  }
  cleanup_query.run();
  Ok(())
}

#[derive(Debug)]
#[repr(C)]
pub(crate) struct SwDeviceCreateCtx {
  create_result: HRESULT,
  device_instance_id: *mut StaticWideCStr<MAX_DEVICE_ID_LEN>,
  triggered: HANDLE,
}

impl SwDeviceCreateCtx {
  pub fn new(id: &mut StaticWideCStr<MAX_DEVICE_ID_LEN>) -> std::io::Result<Self> {
    let triggered = unsafe { CreateEventW(null_mut(), FALSE, FALSE, std::ptr::null()) };
    if !check_handle(triggered) {
      return Err(last_error!("Failed to create event"));
    }
    Ok(Self {
      create_result: 0,
      device_instance_id: id.get_mut_ptr(),
      triggered,
    })
  }
}

impl Drop for SwDeviceCreateCtx {
  fn drop(&mut self) {
    unsafe { CloseHandle(self.triggered) };
  }
}

pub(crate) unsafe extern "system" fn device_create_callback(
  _sw_device: HSWDEVICE,
  create_result: HRESULT,
  context: PVOID,
  device_instance_id: PCWSTR,
) {
  let ctx = &mut *(context as *mut SwDeviceCreateCtx);
  ctx.create_result = create_result;
  if !device_instance_id.is_null() {
    *ctx.device_instance_id =
      StaticWideCStr::<MAX_DEVICE_ID_LEN>::from_ptr_unchecked(device_instance_id, MAX_DEVICE_ID_LEN);
  }
  SetEvent(ctx.triggered);
}

pub(crate) fn adapter_remove_instance(
  dev_info: HDEVINFO,
  dev_info_data: *mut SP_DEVINFO_DATA,
) -> std::io::Result<()> {
  #[cfg(any(target_arch = "x86", target_arch = "arm", target_arch = "x86_64"))]
  if unsafe { get_system_params().native_machine } != IMAGE_FILE_PROCESS {
    return remove_instance(dev_info, dev_info_data);
  }
  let mut remove_device_params = SP_REMOVEDEVICE_PARAMS {
    ClassInstallHeader: SP_CLASSINSTALL_HEADER {
      cbSize: std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32,
      InstallFunction: DIF_REMOVE,
    },
    Scope: DI_REMOVEDEVICE_GLOBAL,
    ..unsafe { std::mem::zeroed() }
  };
  let result = unsafe {
    SetupDiSetClassInstallParamsW(
      dev_info,
      dev_info_data,
      remove_device_params.ClassInstallHeader.get_mut_ptr(),
      std::mem::size_of_val(&remove_device_params) as u32,
    )
  };
  if result == FALSE {
    return Err(std::io::Error::last_os_error());
  }
  let result = unsafe { SetupDiCallClassInstaller(DIF_REMOVE, dev_info, dev_info_data) };
  if result == FALSE {
    return Err(std::io::Error::last_os_error());
  }
  Ok(())
}

pub(crate) fn adapter_enable_instance(
  dev_info: HDEVINFO,
  dev_info_data: *mut SP_DEVINFO_DATA,
) -> std::io::Result<()> {
  #[cfg(any(target_arch = "x86", target_arch = "arm", target_arch = "x86_64"))]
  if unsafe { get_system_params().native_machine } != IMAGE_FILE_PROCESS {
    return enable_instance(dev_info, dev_info_data);
  }
  let mut params = SP_PROPCHANGE_PARAMS {
    ClassInstallHeader: SP_CLASSINSTALL_HEADER {
      cbSize: std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32,
      InstallFunction: DIF_PROPERTYCHANGE,
    },
    StateChange: DICS_ENABLE,
    Scope: DICS_FLAG_GLOBAL,
    ..unsafe { std::mem::zeroed() }
  };
  let result = unsafe {
    SetupDiSetClassInstallParamsW(
      dev_info,
      dev_info_data,
      params.ClassInstallHeader.get_mut_ptr(),
      std::mem::size_of_val(&params) as u32,
    )
  };
  if result == FALSE {
    return Err(std::io::Error::last_os_error());
  }
  let result = unsafe { SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, dev_info, dev_info_data) };
  if result == FALSE {
    return Err(std::io::Error::last_os_error());
  }
  Ok(())
}

pub(crate) fn adapter_disable_instance(
  dev_info: HDEVINFO,
  dev_info_data: *mut SP_DEVINFO_DATA,
) -> std::io::Result<()> {
  #[cfg(any(target_arch = "x86", target_arch = "arm", target_arch = "x86_64"))]
  if unsafe { get_system_params().native_machine } != IMAGE_FILE_PROCESS {
    return enable_instance(dev_info, dev_info_data);
  }
  let mut params = SP_PROPCHANGE_PARAMS {
    ClassInstallHeader: SP_CLASSINSTALL_HEADER {
      cbSize: std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32,
      InstallFunction: DIF_PROPERTYCHANGE,
    },
    StateChange: DICS_DISABLE,
    Scope: DICS_FLAG_GLOBAL,
    ..unsafe { std::mem::zeroed() }
  };
  let result = unsafe {
    SetupDiSetClassInstallParamsW(
      dev_info,
      dev_info_data,
      params.ClassInstallHeader.get_mut_ptr(),
      std::mem::size_of_val(&params) as u32,
    )
  };
  if result == FALSE {
    return Err(std::io::Error::last_os_error());
  }
  let result = unsafe { SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, dev_info, dev_info_data) };
  if result == FALSE {
    return Err(std::io::Error::last_os_error());
  }
  Ok(())
}

fn populate_adapter_data(adapter: &mut Adapter) -> std::io::Result<()> {
  let key = RegKey::open(
    adapter.dev_info,
    adapter.dev_info_data.get_mut_ptr(),
    DICS_FLAG_GLOBAL,
    0,
    DIREG_DRV,
    KEY_QUERY_VALUE,
  )?;

  let value_str = registry_query_string(&key, widecstr!("NetCfgInstanceId"), true)?;
  let result = unsafe { CLSIDFromString(value_str.as_ptr(), adapter.cfg_instance_id.get_mut_ptr()) };
  if FAILED(result) {
    let reg_path = logger_get_registry_key_path(&key);
    return Err(last_error!(
      "{}\\NetCfgInstanceId is not a GUID: {}",
      reg_path.display(),
      value_str.display()
    ));
  }
  adapter.luid_index = registry_query_dword(&key, widecstr!("NetLuidIndex"), true)?;
  adapter.if_type = registry_query_dword(&key, widecstr!("*IfType"), true)?;
  adapter.interface_filename = adapter_get_device_object_file_name(adapter.dev_instance_id.as_ref())?;
  key.close();
  Ok(())
}

unsafe extern "system" fn do_orphaned_device_cleanup(_ctx: LPVOID) -> DWORD {
  adapter_cleanup_orphaned_devices();
  ORPHAN_THREAD_IS_WORKING.store(false, std::sync::atomic::Ordering::Relaxed);
  return 0;
}

fn queue_up_orphaned_device_cleanup_routine() {
  if ORPHAN_THREAD_IS_WORKING
    .compare_exchange(
      false,
      true,
      std::sync::atomic::Ordering::SeqCst,
      std::sync::atomic::Ordering::SeqCst,
    )
    .ignore()
    == false
  {
    unsafe { QueueUserWorkItem(Some(do_orphaned_device_cleanup), null_mut(), 0) };
  }
}

pub fn adapter_cleanup_orphaned_devices() {
  let device_installation_mutex = match SystemNamedMutexLock::take_device_installation_mutex() {
    Ok(res) => res,
    Err(_) => {
      last_error!("Failed to take device installation mutex");
      return;
    }
  };

  if unsafe { get_system_params().is_windows7 } {
    cleanup_orphaned_devices_win7();
    return;
  }

  let dev_info = unsafe {
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
  if dev_info == INVALID_HANDLE_VALUE {
    last_error!("Failed to get adapters");
    return;
  }
  unsafe_defer! { destroy_device_info_list <-
    SetupDiDestroyDeviceInfoList(dev_info);
  };
  let mut dev_info_data = unsafe {
    SP_DEVINFO_DATA {
      cbSize: csizeof!(SP_DEVINFO_DATA),
      ..std::mem::zeroed()
    }
  };
  for enum_index in 0.. {
    let result = unsafe { SetupDiEnumDeviceInfo(dev_info, enum_index, dev_info_data.get_mut_ptr()) };
    if result == FALSE {
      if get_last_error_code() == ERROR_NO_MORE_ITEMS {
        break;
      }
      continue;
    }
    let mut status: ULONG = 0;
    let mut code: ULONG = 0;
    let result = unsafe {
      CM_Get_DevNode_Status(
        status.get_mut_ptr(),
        code.get_mut_ptr(),
        dev_info_data.DevInst,
        0,
      )
    };
    if result == CR_SUCCESS && status & DN_HAS_PROBLEM == 0 {
      continue;
    }
    let mut prop_type: DEVPROPTYPE = unsafe { std::mem::zeroed() };
    let mut name = static_widecstr!["<unknown>"; MAX_ADAPTER_NAME];
    unsafe {
      SetupDiGetDevicePropertyW(
        dev_info,
        dev_info_data.get_mut_ptr(),
        DEVPKEY_WINTUN_NAME.get_const_ptr(),
        prop_type.get_mut_ptr(),
        name.as_mut_ptr().cast(),
        name.sizeof(),
        null_mut(),
        0,
      )
    };
    let name: &WideCStr = unsafe { name.as_ref().try_into() }.unwrap_or(widecstr!("<unknown>"));
    let result = adapter_remove_instance(dev_info, dev_info_data.get_mut_ptr());
    if let Err(err) = result {
      error!(
        err,
        "Failed to remove orphaned adapter \"{}\"",
        name.display()
      );
      continue;
    }
    log!(
      crate::logger::Level::Info,
      "Removed orphaned adapter \"{}\"",
      name.display()
    );
  }
  destroy_device_info_list.run();
  device_installation_mutex.release();
}

#[allow(dead_code)]
fn rename_by_net_guid(guid: GUID, name: &WideCStr) -> std::io::Result<()> {
  let dev_info = unsafe {
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
  if dev_info == INVALID_HANDLE_VALUE {
    return Err(std::io::Error::last_os_error());
  }
  unsafe_defer! { destroy_dev_info_list <-
    SetupDiDestroyDeviceInfoList(dev_info) ;
  };
  let mut dev_info_data = SP_DEVINFO_DATA {
    cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as DWORD,
    ..unsafe { std::mem::zeroed() }
  };
  for enum_index in 0.. {
    let result = unsafe { SetupDiEnumDeviceInfo(dev_info, enum_index, dev_info_data.get_mut_ptr()) };
    if result == FALSE {
      if get_last_error_code() == ERROR_NO_MORE_ITEMS {
        break;
      }
      continue;
    }
    let key = unsafe {
      SetupDiOpenDevRegKey(
        dev_info,
        dev_info_data.get_mut_ptr(),
        DICS_FLAG_GLOBAL,
        0,
        DIREG_DRV,
        KEY_QUERY_VALUE,
      )
    };
    if !check_handle(key.cast()) {
      continue;
    }
    let key = RegKey::from_raw(key);
    let Ok(value_str) = registry_query_string(&key, widecstr!("NetCfgInstanceid"), true) else {continue;};
    let mut guid2: GUID = unsafe { std::mem::zeroed() };
    let hret = unsafe { CLSIDFromString(value_str.as_ptr(), guid2.get_mut_ptr()) };
    if FAILED(hret) || guid_eq(guid, guid2) {
      continue;
    }
    let name_size = name.capacity();
    let result = unsafe {
      SetupDiSetDevicePropertyW(
        dev_info,
        dev_info_data.get_mut_ptr(),
        DEVPKEY_WINTUN_NAME.get_const_ptr(),
        DEVPROP_TYPE_STRING,
        name.as_ptr() as *const u8,
        name_size,
        0,
      )
    };
    if result == FALSE {
      return Err(std::io::Error::last_os_error());
    }
    return Ok(());
  }
  destroy_dev_info_list.run();
  Err(error!(
    ERROR_NOT_FOUND,
    "Failed to get device by GUID: {:?}", guid
  ))
}

#[allow(dead_code)]
pub fn convert_interface_alias_to_guid(name: &WideCStr) -> std::io::Result<GUID> {
  let mut luid: NET_LUID = unsafe { std::mem::zeroed() };
  let result = unsafe { ConvertInterfaceAliasToLuid(name.as_ptr(), luid.get_mut_ptr()) };
  if result != NO_ERROR {
    return Err(error!(
      result,
      "Failed convert interface {} name to the locally unique identifier",
      name.display()
    ));
  }
  let mut guid: GUID = unsafe { std::mem::zeroed() };
  let result = unsafe { ConvertInterfaceLuidToGuid(luid.get_const_ptr(), guid.get_mut_ptr()) };
  if result != NO_ERROR {
    return Err(error!(
      result,
      "Failed to convert interface {} LUID ({}) to GUID",
      name.display(),
      luid.Value
    ));
  }
  Ok(guid)
}

pub fn nci_set_adapter_name(guid: GUID, name: &WideCStr) -> std::io::Result<WideCString> {
  const MAX_SUFFIX: u32 = 1000;
  if name.len_usize() >= MAX_ADAPTER_NAME {
    let err = std::io::Error::from_raw_os_error(ERROR_BUFFER_OVERFLOW as i32);
    return Err(err);
  }
  let avaliable_name = name.to_owned();
  for _i in 0..MAX_SUFFIX {
    match set_connection_name(guid, avaliable_name.as_ref()) {
      Ok(()) => return Ok(avaliable_name),
      Err(err) if err.raw_os_error().unwrap() == ERROR_DUP_NAME as i32 => {}
      Err(err) => return Err(err),
    };
    todo!("Trying another name is not implemented")
  }
  Err(std::io::Error::from_raw_os_error(ERROR_DUP_NAME as i32))
}
