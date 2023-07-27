use cutils::{
  check_handle, csizeof,
  errors::get_last_error_code,
  files::WindowsFile,
  inspection::GetPtrExt,
  static_widecstr,
  strings::{StaticWideCStr, WideCStr},
  unsafe_defer, wide_array, widecstr,
};
use winapi::{
  shared::{
    cfg::DN_HAS_PROBLEM,
    devguid::GUID_DEVCLASS_NET,
    devpkey::DEVPKEY_Device_ProblemCode,
    devpropdef::{
      DEVPROPID_FIRST_USABLE, DEVPROPKEY, DEVPROPTYPE, DEVPROP_TYPE_BINARY, DEVPROP_TYPE_INT32,
      DEVPROP_TYPE_STRING, DEVPROP_TYPE_UINT32,
    },
    minwindef::{DWORD, FALSE, FILETIME, TRUE},
    ntdef::WCHAR,
    winerror::{
      ERROR_DEVICE_REINITIALIZATION_NEEDED, ERROR_INVALID_DATA, ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT,
    },
  },
  um::{
    cfgmgr32::{CM_Get_DevNode_Status, CR_SUCCESS},
    handleapi::CloseHandle,
    ipexport::MAX_ADAPTER_NAME,
    processthreadsapi::{GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, OpenProcess},
    setupapi::{
      SetupDiBuildDriverInfoList, SetupDiCallClassInstaller, SetupDiCreateDeviceInfoListExW,
      SetupDiCreateDeviceInfoW, SetupDiDestroyDeviceInfoList, SetupDiDestroyDriverInfoList,
      SetupDiEnumDeviceInfo, SetupDiEnumDriverInfoW, SetupDiGetClassDevsExW,
      SetupDiGetDeviceInstallParamsW, SetupDiGetDeviceInstanceIdW, SetupDiGetDevicePropertyW,
      SetupDiGetDeviceRegistryPropertyW, SetupDiOpenDeviceInfoW, SetupDiSetDeviceInstallParamsW,
      SetupDiSetDevicePropertyW, SetupDiSetDeviceRegistryPropertyW, SetupDiSetSelectedDevice,
      SetupDiSetSelectedDriverW, DICD_GENERATE_ID, DICS_FLAG_GLOBAL, DIF_INSTALLDEVICE,
      DIF_INSTALLINTERFACES, DIF_REGISTERDEVICE, DIF_REGISTER_COINSTALLERS, DIOD_INHERIT_CLASSDRVS,
      DIREG_DRV, DI_QUIETINSTALL, ERROR_DRIVER_INSTALL_BLOCKED, HDEVINFO, SPDIT_COMPATDRIVER,
      SPDRP_DEVICEDESC, SPDRP_FRIENDLYNAME, SPDRP_HARDWAREID, SP_DEVINFO_DATA,
      SP_DEVINSTALL_PARAMS_W, SP_DRVINFO_DATA_W,
    },
    winnt::{KEY_QUERY_VALUE, PROCESS_QUERY_LIMITED_INFORMATION},
    winreg::RegQueryValueExW,
  },
};

use crate::{
  adapter::{
    Adapter, adapter_get_device_object_file_name, adapter_remove_instance, DEVPKEY_WINTUN_NAME,
    WINTUN_ENUMERATOR, WINTUN_HWID,
  },
  logger::{error, info, last_error, IntoError},
  registry::RegKey,
  rundll32::*,
  wmain::{get_system_params, IMAGE_FILE_PROCESS},
};

const DEVPKEY_WINTUN_OWNING_PROCESS: DEVPROPKEY = DEVPROPKEY {
  fmtid: winapi::shared::guiddef::GUID {
    Data1: 0x3361c968,
    Data2: 0x2f2e,
    Data3: 0x4660,
    Data4: [0xb4, 0x7e, 0x69, 0x9c, 0xdc, 0x4c, 0x32, 0xb9],
  },
  pid: DEVPROPID_FIRST_USABLE + 3,
};

#[repr(C)]
pub struct OwningProcess {
  process_id: DWORD,
  creation_time: FILETIME,
}

pub fn wait_for_interface_win7(
  dev_info: HDEVINFO,
  dev_info_data: &mut SP_DEVINFO_DATA,
  dev_instance_id: &WideCStr,
) -> std::io::Result<()> {
  const MAX_TRIES: usize = 1500;
  const SLEEP_TIME: std::time::Duration = std::time::Duration::from_millis(10);
  let mut key = None;
  let mut file_name = None;
  let mut file = None;
  let mut val_type: DWORD = 0;
  let mut status = 0;
  let mut number = 0;
  for tries in 0..MAX_TRIES {
    if tries != 0 {
      std::thread::sleep(SLEEP_TIME);
    }
    if key.is_none() {
      key = RegKey::open(
        dev_info,
        dev_info_data,
        DICS_FLAG_GLOBAL,
        0,
        DIREG_DRV,
        KEY_QUERY_VALUE,
      )
      .ok();
    }
    if file_name.is_none() {
      file_name = adapter_get_device_object_file_name(dev_instance_id).ok();
    }
    if let Some(file_name) = file_name.as_ref() {
      if file.is_none() {
        file = WindowsFile::options()
          .read(true)
          .write(true)
          .reset_sharing(true)
          .reset_flags_and_attributes(0)
          .open_existing(&file_name)
          .ok();
      }
    }
    if let Some(key) = key.as_ref() {
      let mut zero = 0;
      if file_name.is_some()
        && file.is_some()
        && unsafe {
          RegQueryValueExW(
            key.as_raw(),
            widecstr!("NetCfgInstanceId").as_ptr(),
            std::ptr::null_mut(),
            val_type.get_mut_ptr(),
            std::ptr::null_mut(),
            zero.get_mut_ptr(),
          ) != FALSE
            && CM_Get_DevNode_Status(
              status.get_mut_ptr(),
              number.get_mut_ptr(),
              dev_info_data.DevInst,
              0,
            ) == CR_SUCCESS
        }
        && status & DN_HAS_PROBLEM == 0
        && number == 0
      {
        return Ok(());
      }
    }
  }
  Err(ERROR_TIMEOUT.into_error())
}

pub fn create_adapter_win7(
  adapter: &mut Adapter,
  name: &WideCStr,
  tunnel_type: &WideCStr,
) -> std::io::Result<()> {
  let dev_info = unsafe {
    SetupDiCreateDeviceInfoListExW(
      GUID_DEVCLASS_NET.get_const_ptr(),
      std::ptr::null_mut(),
      std::ptr::null(),
      std::ptr::null_mut(),
    )
  };
  if !check_handle(dev_info) {
    return Err(last_error!("Failed to create empty device information set"));
  }
  let mut dev_info_data = SP_DEVINFO_DATA {
    cbSize: csizeof!(SP_DEVINFO_DATA),
    ..unsafe { std::mem::zeroed() }
  };
  let dev_info_data_ptr = dev_info_data.get_mut_ptr();
  let native_machine = unsafe { get_system_params().native_machine };
  #[cfg(any(target_arch = "x86", target_arch = "arm", target_arch = "x86_64"))]
  if native_machine != IMAGE_FILE_PROCESS {
    adapter.dev_instance_id =
      create_instance().map_err(|err| error!(err, "Failed to create device instance"))?;
    unsafe_defer! { cleanup_dev_info <-
      SetupDiDestroyDeviceInfoList(dev_info);
    }
    if unsafe {
      SetupDiOpenDeviceInfoW(
        dev_info,
        adapter.dev_instance_id.as_ptr(),
        std::ptr::null_mut(),
        DIOD_INHERIT_CLASSDRVS,
        dev_info_data_ptr,
      )
    } == FALSE
    {
      return Err(last_error!("Failed to open device info"));
    }
    cleanup_dev_info.forget();
  }
  if cfg!(not(any(
    target_arch = "x86",
    target_arch = "arm",
    target_arch = "x86_64"
  )))
    || native_machine != IMAGE_FILE_PROCESS
  {
    init_instance_not_wow64(dev_info, tunnel_type, dev_info_data_ptr)?;
  }
  unsafe_defer! { cleanup_dev_info <-
    SetupDiDestroyDeviceInfoList(dev_info);
  }
  unsafe_defer! { cleanup_driver_info <-
    SetupDiDestroyDriverInfoList(dev_info, dev_info_data_ptr, SPDIT_COMPATDRIVER);
  };
  unsafe_defer! { cleanup_device <- move
    drop(adapter_remove_instance(dev_info, dev_info_data_ptr));
  };
  let mut owning_process = unsafe {
    OwningProcess {
      process_id: GetCurrentProcessId(),
      ..std::mem::zeroed()
    }
  };
  let mut unused: FILETIME = unsafe { std::mem::zeroed() };
  if FALSE
    == unsafe {
      GetProcessTimes(
        GetCurrentProcess(),
        owning_process.creation_time.get_mut_ptr(),
        unused.get_mut_ptr(),
        unused.get_mut_ptr(),
        unused.get_mut_ptr(),
      )
    }
  {
    return Err(last_error!("Failed to get process creation time"));
  }

  if FALSE
    == unsafe {
      SetupDiSetDeviceRegistryPropertyW(
        dev_info,
        dev_info_data_ptr,
        SPDRP_FRIENDLYNAME,
        tunnel_type.as_ptr().cast(),
        tunnel_type.sizeof(),
      )
    }
    || FALSE
      == unsafe {
        SetupDiSetDeviceRegistryPropertyW(
          dev_info,
          dev_info_data_ptr,
          SPDRP_DEVICEDESC,
          tunnel_type.as_ptr().cast(),
          tunnel_type.sizeof(),
        )
      }
    || FALSE
      == unsafe {
        SetupDiSetDevicePropertyW(
          dev_info,
          dev_info_data_ptr,
          DEVPKEY_WINTUN_NAME.get_const_ptr(),
          DEVPROP_TYPE_STRING,
          name.as_ptr().cast(),
          name.sizeof(),
          0,
        )
      }
    || FALSE
      == unsafe {
        SetupDiSetDevicePropertyW(
          dev_info,
          dev_info_data_ptr,
          DEVPKEY_WINTUN_OWNING_PROCESS.get_const_ptr(),
          DEVPROP_TYPE_BINARY,
          owning_process.get_const_ptr().cast(),
          csizeof!(=owning_process),
          0,
        )
      }
  {
    return Err(last_error!("Failed to set device properties"));
  }

  let mut required_chars: DWORD = adapter.dev_instance_id.capacity();
  if FALSE
    == unsafe {
      SetupDiGetDeviceInstanceIdW(
        dev_info,
        dev_info_data_ptr,
        adapter.dev_instance_id.as_mut_ptr(),
        required_chars,
        required_chars.get_mut_ptr(),
      )
    }
  {
    return Err(last_error!("Failed to get adapter instance ID"));
  }

  if wait_for_interface_win7(dev_info, &mut dev_info_data, &adapter.dev_instance_id).is_err() {
    let mut property_type: DEVPROPTYPE = 0;
    let mut problem_code: i32 = 0;
    if FALSE
      == unsafe {
        SetupDiGetDevicePropertyW(
          dev_info,
          dev_info_data_ptr,
          DEVPKEY_Device_ProblemCode.get_const_ptr(),
          property_type.get_mut_ptr(),
          problem_code.get_mut_ptr().cast(),
          csizeof!(=problem_code),
          std::ptr::null_mut(),
          0,
        )
      }
      || (property_type != DEVPROP_TYPE_INT32 && property_type != DEVPROP_TYPE_UINT32)
    {
      problem_code = 0;
    }
    return Err(error!(
      ERROR_DEVICE_REINITIALIZATION_NEEDED,
      "Failed to setup adapter (problem code: 0x{:x})", problem_code
    ));
  }

  cleanup_device.forget();
  cleanup_driver_info.run();
  cleanup_dev_info.run();
  Ok(())
}

fn init_instance_not_wow64(
  dev_info: HDEVINFO,
  tunnel_type: &WideCStr,
  dev_info_data_ptr: *mut SP_DEVINFO_DATA,
) -> std::io::Result<()> {
  if unsafe {
    SetupDiCreateDeviceInfoW(
      dev_info,
      WINTUN_HWID.as_ptr(),
      GUID_DEVCLASS_NET.get_const_ptr(),
      tunnel_type.as_ptr(),
      std::ptr::null_mut(),
      DICD_GENERATE_ID,
      dev_info_data_ptr,
    )
  } == FALSE
  {
    return Err(last_error!(
      "Failed to create new device information element"
    ));
  }
  let mut dev_install_params = SP_DEVINSTALL_PARAMS_W {
    cbSize: csizeof!(SP_DEVINSTALL_PARAMS_W),
    ..unsafe { std::mem::zeroed() }
  };
  if unsafe {
    SetupDiGetDeviceInstallParamsW(dev_info, dev_info_data_ptr, dev_install_params.get_mut_ptr())
  } == FALSE
  {
    return Err(last_error!(
      "Failed to retrieve adapter device installation parameters"
    ));
  }
  dev_install_params.Flags |= DI_QUIETINSTALL;
  if unsafe {
    SetupDiSetDeviceInstallParamsW(dev_info, dev_info_data_ptr, dev_install_params.get_mut_ptr())
  } == FALSE
  {
    return Err(last_error!(
      "Failed to set adapter device installation parameters"
    ));
  }
  if FALSE == unsafe { SetupDiSetSelectedDevice(dev_info, dev_info_data_ptr) } {
    return Err(last_error!("Failed to select adapter device"));
  }
  const HWIDS: [WCHAR; 8] = wide_array!("Wintun"; 8);
  // static const WCHAR Hwids[_countof(WINTUN_HWID) + 1 /*Multi-string terminator*/] = WINTUN_HWID;
  if FALSE
    == unsafe {
      SetupDiSetDeviceRegistryPropertyW(
        dev_info,
        dev_info_data_ptr,
        SPDRP_HARDWAREID,
        HWIDS.as_ptr().cast(),
        csizeof!(=HWIDS),
      )
    }
  {
    return Err(last_error!("Failed to set adapter hardware ID"));
  }
  if FALSE == unsafe { SetupDiBuildDriverInfoList(dev_info, dev_info_data_ptr, SPDIT_COMPATDRIVER) }
  {
    return Err(last_error!("Failed building adapter driver info list"));
  }
  unsafe_defer! { cleanup_driver_info <-
    SetupDiDestroyDriverInfoList(dev_info, dev_info_data_ptr, SPDIT_COMPATDRIVER);
  };
  let mut drv_info_data = SP_DRVINFO_DATA_W {
    cbSize: csizeof!(SP_DRVINFO_DATA_W),
    ..unsafe { std::mem::zeroed() }
  };
  if FALSE
    == unsafe {
      SetupDiEnumDriverInfoW(
        dev_info,
        dev_info_data_ptr,
        SPDIT_COMPATDRIVER,
        0,
        drv_info_data.get_mut_ptr(),
      )
    }
    || FALSE
      == unsafe {
        SetupDiSetSelectedDriverW(dev_info, dev_info_data_ptr, drv_info_data.get_mut_ptr())
      }
  {
    return Err(error!(
      ERROR_DRIVER_INSTALL_BLOCKED,
      "Failed to select a driver"
    ));
  }

  if FALSE == unsafe { SetupDiCallClassInstaller(DIF_REGISTERDEVICE, dev_info, dev_info_data_ptr) }
  {
    return Err(last_error!("Failed to register adapter device"));
  }
  if FALSE
    == unsafe { SetupDiCallClassInstaller(DIF_REGISTER_COINSTALLERS, dev_info, dev_info_data_ptr) }
  {
    last_error!("Failed to register adapter coinstallers");
  }
  if FALSE
    == unsafe { SetupDiCallClassInstaller(DIF_INSTALLINTERFACES, dev_info, dev_info_data_ptr) }
  {
    last_error!("Failed to install adapter interfaces");
  }
  unsafe_defer! { cleanup_device <- move
    drop(adapter_remove_instance(dev_info, dev_info_data_ptr));
  };
  if FALSE == unsafe { SetupDiCallClassInstaller(DIF_INSTALLDEVICE, dev_info, dev_info_data_ptr) } {
    return Err(last_error!("Failed to install adapter device"));
  }
  cleanup_device.forget();
  cleanup_driver_info.forget();
  Ok(())
}

pub fn create_adapter_post_win7(adapter: &mut Adapter, tunnel_type: &WideCStr) {
  unsafe {
    SetupDiSetDeviceRegistryPropertyW(
      adapter.dev_info,
      adapter.dev_info_data.get_mut_ptr(),
      SPDRP_FRIENDLYNAME,
      tunnel_type.as_ptr().cast(),
      tunnel_type.sizeof(),
    )
  };
  unsafe {
    SetupDiSetDeviceRegistryPropertyW(
      adapter.dev_info,
      adapter.dev_info_data.get_mut_ptr(),
      SPDRP_DEVICEDESC,
      tunnel_type.as_ptr().cast(),
      tunnel_type.sizeof(),
    )
  };
}

pub fn process_is_stale(owning_process: &mut OwningProcess) -> bool {
  let process = unsafe {
    OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION,
      FALSE,
      owning_process.process_id,
    )
  };
  if !check_handle(process) {
    return true;
  }
  let mut creation_time: FILETIME = unsafe { std::mem::zeroed() };
  let mut unused: FILETIME = unsafe { std::mem::zeroed() };
  unsafe_defer! { cleanup_process <-
    CloseHandle(process);
  }
  if unsafe {
    GetProcessTimes(
      process,
      creation_time.get_mut_ptr(),
      unused.get_mut_ptr(),
      unused.get_mut_ptr(),
      unused.get_mut_ptr(),
    )
  } == FALSE
  {
    return false;
  }
  cleanup_process.run();
  return creation_time.dwHighDateTime == owning_process.creation_time.dwHighDateTime
    && creation_time.dwLowDateTime == owning_process.creation_time.dwLowDateTime;
}

pub fn cleanup_orphaned_devices_win7() {
  let dev_info = unsafe {
    SetupDiGetClassDevsExW(
      GUID_DEVCLASS_NET.get_const_ptr(),
      WINTUN_ENUMERATOR!().as_ptr(),
      std::ptr::null_mut(),
      0,
      std::ptr::null_mut(),
      std::ptr::null(),
      std::ptr::null_mut(),
    )
  };
  if !check_handle(dev_info) {
    if get_last_error_code() != ERROR_INVALID_DATA {
      last_error!("Failed to get adapters");
    }
    return;
  }

  let mut dev_info_data = SP_DEVINFO_DATA {
    cbSize: csizeof!(SP_DEVINFO_DATA),
    ..unsafe { std::mem::zeroed() }
  };
  for enum_index in 0.. {
    if FALSE == unsafe { SetupDiEnumDeviceInfo(dev_info, enum_index, dev_info_data.get_mut_ptr()) } {
      if get_last_error_code() == ERROR_NO_MORE_ITEMS {
        break;
      }
      continue;
    }

    let mut owning_process: OwningProcess = unsafe { std::mem::zeroed() };
    let mut prop_type: DEVPROPTYPE = 0;
    if TRUE
      == unsafe {
        SetupDiGetDevicePropertyW(
          dev_info,
          dev_info_data.get_mut_ptr(),
          DEVPKEY_WINTUN_OWNING_PROCESS.get_const_ptr(),
          prop_type.get_mut_ptr(),
          owning_process.get_mut_ptr().cast(),
          csizeof!(=owning_process),
          std::ptr::null_mut(),
          0,
        )
      }
      && prop_type == DEVPROP_TYPE_BINARY
      && !process_is_stale(&mut owning_process)
    {
      continue;
    }

    let mut name = static_widecstr!("<unknown>"; MAX_ADAPTER_NAME);
    unsafe {
      SetupDiGetDevicePropertyW(
        dev_info,
        dev_info_data.get_mut_ptr(),
        DEVPKEY_WINTUN_NAME.get_const_ptr(),
        prop_type.get_mut_ptr(),
        name.get_mut_ptr().cast(),
        name.sizeof(),
        std::ptr::null_mut(),
        0,
      )
    };
    if let Err(err) = adapter_remove_instance(dev_info, dev_info_data.get_mut_ptr()) {
      error!(
        err,
        "Failed to remove orphaned adapter \"{}\"",
        name.display()
      );
      continue;
    }
    info!("Removed orphaned adapter \"{}\"", name.display());
  }
  unsafe { SetupDiDestroyDeviceInfoList(dev_info) };
}

pub fn cleanup_lagacy_devices() {
  let dev_info = unsafe {
    SetupDiGetClassDevsExW(
      GUID_DEVCLASS_NET.get_const_ptr(),
      widecstr!(r"ROOT\NET").as_ptr(),
      std::ptr::null_mut(),
      0,
      std::ptr::null_mut(),
      std::ptr::null(),
      std::ptr::null_mut(),
    )
  };
  if !check_handle(dev_info) {
    return;
  }
  let mut dev_info_data = SP_DEVINFO_DATA {
    cbSize: csizeof!(SP_DEVINFO_DATA),
    ..unsafe { std::mem::zeroed() }
  };
  for enum_index in 0.. {
    if FALSE == unsafe { SetupDiEnumDeviceInfo(dev_info, enum_index, dev_info_data.get_mut_ptr()) } {
      if get_last_error_code() == ERROR_NO_MORE_ITEMS {
        break;
      }
      continue;
    }
    let mut hardware_ids = StaticWideCStr::<0x400>::zeroed();
    let mut value_type = 0;
    let mut size = hardware_ids.sizeof();
    if FALSE
      == unsafe {
        SetupDiGetDeviceRegistryPropertyW(
          dev_info,
          dev_info_data.get_mut_ptr(),
          SPDRP_HARDWAREID,
          value_type.get_mut_ptr(),
          hardware_ids.get_mut_ptr().cast(),
          size,
          size.get_mut_ptr(),
        )
      }
      || size > hardware_ids.sizeof()
    {
      continue;
    }
    for s in hardware_ids.iter_strs() {
      if s == WINTUN_HWID {
        drop(adapter_remove_instance(dev_info, dev_info_data.get_mut_ptr()));
        break;
      }
    }
  }
  unsafe { SetupDiDestroyDeviceInfoList(dev_info) };
}
