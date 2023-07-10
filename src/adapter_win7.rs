use cutils::{
  check_handle, csizeof,
  deferred::Deferred,
  files::WindowsFile,
  inspection::{GetPtrExt, InitZeroed},
  static_widecstr,
  strings::{StaticWideCStr, U16CStr, WideCStr},
  unsafe_defer, wide_array, widecstr,
};
use get_last_error::Win32Error;
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
    handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
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
    AdapterGetDeviceObjectFileName, AdapterRemoveInstance, DEVPKEY_Wintun_Name, WINTUN_ADAPTER,
    WINTUN_ENUMERATOR, WINTUN_HWID,
  },
  logger::{error, info, last_error, IntoError},
  registry::RegKey,
  rundll32::create_instance,
  wmain::{get_system_params, IMAGE_FILE_PROCESS},
};

const DEVPKEY_Wintun_OwningProcess: DEVPROPKEY = DEVPROPKEY {
  fmtid: winapi::shared::guiddef::GUID {
    Data1: 0x3361c968,
    Data2: 0x2f2e,
    Data3: 0x4660,
    Data4: [0xb4, 0x7e, 0x69, 0x9c, 0xdc, 0x4c, 0x32, 0xb9],
  },
  pid: DEVPROPID_FIRST_USABLE + 3,
};

#[repr(C)]
pub struct OWNING_PROCESS {
  ProcessId: DWORD,
  CreationTime: FILETIME,
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
      file_name = AdapterGetDeviceObjectFileName(dev_instance_id).ok();
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
  adapter: &mut WINTUN_ADAPTER,
  name: &WideCStr,
  tunnel_type: &WideCStr,
) -> std::io::Result<()> {
  let mut dev_info = unsafe {
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
  let native_machine = unsafe { get_system_params().NativeMachine };
  #[cfg(feature = "wow64_support")]
  if native_machine != IMAGE_FILE_PROCESS {
    if let Err(err) = create_instance(&mut adapter.DevInstanceID) {
      return Err(error!(err, "Failed to create device instance"));
    }
    unsafe_defer! { cleanupDevInfo <-
      SetupDiDestroyDeviceInfoList(dev_info);
    }
    if unsafe {
      SetupDiOpenDeviceInfoW(
        dev_info,
        adapter.DevInstanceID.as_ptr(),
        std::ptr::null_mut(),
        DIOD_INHERIT_CLASSDRVS,
        dev_info_data_ptr,
      )
    } == FALSE
    {
      return Err(last_error!("Failed to open device info"));
    }
    cleanupDevInfo.forget();
  }
  if cfg!(not(feature = "wow64_support")) || native_machine != IMAGE_FILE_PROCESS {
    init_instance_not_wow64(dev_info, tunnel_type, dev_info_data_ptr)?;
  }
  unsafe_defer! { cleanupDevInfo <-
    SetupDiDestroyDeviceInfoList(dev_info);
  }
  unsafe_defer! { cleanupDriverInfo <-
    SetupDiDestroyDriverInfoList(dev_info, dev_info_data_ptr, SPDIT_COMPATDRIVER);
  };
  unsafe_defer! { cleanupDevice <- move
    AdapterRemoveInstance(dev_info, dev_info_data_ptr);
  };
  let mut OwningProcess = unsafe {
    OWNING_PROCESS {
      ProcessId: GetCurrentProcessId(),
      ..std::mem::zeroed()
    }
  };
  let mut Unused: FILETIME = unsafe { std::mem::zeroed() };
  if FALSE
    == unsafe {
      GetProcessTimes(
        GetCurrentProcess(),
        OwningProcess.CreationTime.get_mut_ptr(),
        Unused.get_mut_ptr(),
        Unused.get_mut_ptr(),
        Unused.get_mut_ptr(),
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
          DEVPKEY_Wintun_Name.get_const_ptr(),
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
          DEVPKEY_Wintun_OwningProcess.get_const_ptr(),
          DEVPROP_TYPE_BINARY,
          OwningProcess.get_const_ptr().cast(),
          csizeof!(=OwningProcess),
          0,
        )
      }
  {
    return Err(last_error!("Failed to set device properties"));
  }

  let mut RequiredChars: DWORD = adapter.DevInstanceID.capacity();
  if FALSE
    == unsafe {
      SetupDiGetDeviceInstanceIdW(
        dev_info,
        dev_info_data_ptr,
        adapter.DevInstanceID.as_mut_ptr(),
        RequiredChars,
        RequiredChars.get_mut_ptr(),
      )
    }
  {
    return Err(last_error!("Failed to get adapter instance ID"));
  }

  if wait_for_interface_win7(dev_info, &mut dev_info_data, &adapter.DevInstanceID).is_err() {
    let mut PropertyType: DEVPROPTYPE = 0;
    let mut ProblemCode: i32 = 0;
    if FALSE
      == unsafe {
        SetupDiGetDevicePropertyW(
          dev_info,
          dev_info_data_ptr,
          DEVPKEY_Device_ProblemCode.get_const_ptr(),
          PropertyType.get_mut_ptr(),
          ProblemCode.get_mut_ptr().cast(),
          csizeof!(=ProblemCode),
          std::ptr::null_mut(),
          0,
        )
      }
      || (PropertyType != DEVPROP_TYPE_INT32 && PropertyType != DEVPROP_TYPE_UINT32)
    {
      ProblemCode = 0;
    }
    return Err(error!(
      ERROR_DEVICE_REINITIALIZATION_NEEDED,
      "Failed to setup adapter (problem code: 0x{:x})", ProblemCode
    ));
  }

  cleanupDevice.forget();
  cleanupDriverInfo.run();
  cleanupDevInfo.run();
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
  let mut DevInstallParams = SP_DEVINSTALL_PARAMS_W {
    cbSize: csizeof!(SP_DEVINSTALL_PARAMS_W),
    ..unsafe { std::mem::zeroed() }
  };
  if unsafe {
    SetupDiGetDeviceInstallParamsW(dev_info, dev_info_data_ptr, DevInstallParams.get_mut_ptr())
  } == FALSE
  {
    return Err(last_error!(
      "Failed to retrieve adapter device installation parameters"
    ));
  }
  DevInstallParams.Flags |= DI_QUIETINSTALL;
  if unsafe {
    SetupDiSetDeviceInstallParamsW(dev_info, dev_info_data_ptr, DevInstallParams.get_mut_ptr())
  } == FALSE
  {
    return Err(last_error!(
      "Failed to set adapter device installation parameters"
    ));
  }
  if FALSE == unsafe { SetupDiSetSelectedDevice(dev_info, dev_info_data_ptr) } {
    return Err(last_error!("Failed to select adapter device"));
  }
  const Hwids: [WCHAR; 8] = wide_array!("Wintun"; 8);
  // static const WCHAR Hwids[_countof(WINTUN_HWID) + 1 /*Multi-string terminator*/] = WINTUN_HWID;
  if FALSE
    == unsafe {
      SetupDiSetDeviceRegistryPropertyW(
        dev_info,
        dev_info_data_ptr,
        SPDRP_HARDWAREID,
        Hwids.as_ptr().cast(),
        csizeof!(=Hwids),
      )
    }
  {
    return Err(last_error!("Failed to set adapter hardware ID"));
  }
  if FALSE == unsafe { SetupDiBuildDriverInfoList(dev_info, dev_info_data_ptr, SPDIT_COMPATDRIVER) }
  {
    return Err(last_error!("Failed building adapter driver info list"));
  }
  unsafe_defer! { cleanupDriverInfo <-
    SetupDiDestroyDriverInfoList(dev_info, dev_info_data_ptr, SPDIT_COMPATDRIVER);
  };
  let mut DrvInfoData = SP_DRVINFO_DATA_W {
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
        DrvInfoData.get_mut_ptr(),
      )
    }
    || FALSE
      == unsafe {
        SetupDiSetSelectedDriverW(dev_info, dev_info_data_ptr, DrvInfoData.get_mut_ptr())
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
  unsafe_defer! { cleanupDevice <- move
    AdapterRemoveInstance(dev_info, dev_info_data_ptr);
  };
  if FALSE == unsafe { SetupDiCallClassInstaller(DIF_INSTALLDEVICE, dev_info, dev_info_data_ptr) } {
    return Err(last_error!("Failed to install adapter device"));
  }
  cleanupDevice.forget();
  cleanupDriverInfo.forget();
  Ok(())
}

pub fn create_adapter_post_win7(adapter: &mut WINTUN_ADAPTER, tunnel_type: &WideCStr) {
  unsafe {
    SetupDiSetDeviceRegistryPropertyW(
      adapter.DevInfo,
      adapter.DevInfoData.get_mut_ptr(),
      SPDRP_FRIENDLYNAME,
      tunnel_type.as_ptr().cast(),
      tunnel_type.sizeof(),
    )
  };
  unsafe {
    SetupDiSetDeviceRegistryPropertyW(
      adapter.DevInfo,
      adapter.DevInfoData.get_mut_ptr(),
      SPDRP_DEVICEDESC,
      tunnel_type.as_ptr().cast(),
      tunnel_type.sizeof(),
    )
  };
}

pub fn process_is_stale(owning_process: &mut OWNING_PROCESS) -> bool {
  let Process = unsafe {
    OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION,
      FALSE,
      owning_process.ProcessId,
    )
  };
  if !check_handle(Process) {
    return true;
  }
  let mut CreationTime: FILETIME = unsafe { std::mem::zeroed() };
  let mut Unused: FILETIME = unsafe { std::mem::zeroed() };
  unsafe_defer! { cleanupProcess <-
    CloseHandle(Process);
  }
  if unsafe {
    GetProcessTimes(
      Process,
      CreationTime.get_mut_ptr(),
      Unused.get_mut_ptr(),
      Unused.get_mut_ptr(),
      Unused.get_mut_ptr(),
    )
  } == FALSE
  {
    return false;
  }
  cleanupProcess.run();
  return CreationTime.dwHighDateTime == owning_process.CreationTime.dwHighDateTime
    && CreationTime.dwLowDateTime == owning_process.CreationTime.dwLowDateTime;
}

pub fn cleanup_orphaned_devices_win7() {
  let DevInfo = unsafe {
    SetupDiGetClassDevsExW(
      GUID_DEVCLASS_NET.get_const_ptr(),
      WINTUN_ENUMERATOR.as_ptr(),
      std::ptr::null_mut(),
      0,
      std::ptr::null_mut(),
      std::ptr::null(),
      std::ptr::null_mut(),
    )
  };
  if !check_handle(DevInfo) {
    if Win32Error::get_last_error().code() != ERROR_INVALID_DATA {
      last_error!("Failed to get adapters");
    }
    return;
  }

  let mut DevInfoData = SP_DEVINFO_DATA {
    cbSize: csizeof!(SP_DEVINFO_DATA),
    ..unsafe { std::mem::zeroed() }
  };
  for EnumIndex in 0.. {
    if FALSE == unsafe { SetupDiEnumDeviceInfo(DevInfo, EnumIndex, DevInfoData.get_mut_ptr()) } {
      if Win32Error::get_last_error().code() == ERROR_NO_MORE_ITEMS {
        break;
      }
      continue;
    }

    let mut OwningProcess = unsafe { OWNING_PROCESS::init_zeroed() };
    let mut PropType: DEVPROPTYPE = 0;
    if TRUE
      == unsafe {
        SetupDiGetDevicePropertyW(
          DevInfo,
          DevInfoData.get_mut_ptr(),
          DEVPKEY_Wintun_OwningProcess.get_const_ptr(),
          PropType.get_mut_ptr(),
          OwningProcess.get_mut_ptr().cast(),
          csizeof!(=OwningProcess),
          std::ptr::null_mut(),
          0,
        )
      }
      && PropType == DEVPROP_TYPE_BINARY
      && !process_is_stale(&mut OwningProcess)
    {
      continue;
    }

    let mut Name = static_widecstr!("<unknown>"; MAX_ADAPTER_NAME);
    unsafe {
      SetupDiGetDevicePropertyW(
        DevInfo,
        DevInfoData.get_mut_ptr(),
        DEVPKEY_Wintun_Name.get_const_ptr(),
        PropType.get_mut_ptr(),
        Name.get_mut_ptr().cast(),
        Name.sizeof(),
        std::ptr::null_mut(),
        0,
      )
    };
    if let Err(err) = AdapterRemoveInstance(DevInfo, DevInfoData.get_mut_ptr()) {
      error!(
        err,
        "Failed to remove orphaned adapter \"{}\"",
        Name.display()
      );
      continue;
    }
    info!("Removed orphaned adapter \"{}\"", Name.display());
  }
  unsafe { SetupDiDestroyDeviceInfoList(DevInfo) };
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
  for EnumIndex in 0.. {
    if FALSE == unsafe { SetupDiEnumDeviceInfo(dev_info, EnumIndex, dev_info_data.get_mut_ptr()) } {
      if Win32Error::get_last_error().code() == ERROR_NO_MORE_ITEMS {
        break;
      }
      continue;
    }
    let mut HardwareIDs = StaticWideCStr::<0x400>::zeroed();
    let mut ValueType = 0;
    let mut Size = HardwareIDs.sizeof();
    if FALSE
      == unsafe {
        SetupDiGetDeviceRegistryPropertyW(
          dev_info,
          dev_info_data.get_mut_ptr(),
          SPDRP_HARDWAREID,
          ValueType.get_mut_ptr(),
          HardwareIDs.get_mut_ptr().cast(),
          Size,
          Size.get_mut_ptr(),
        )
      }
      || Size > HardwareIDs.sizeof()
    {
      continue;
    }
    for s in HardwareIDs.iter_strs() {
      if s == WINTUN_HWID {
        AdapterRemoveInstance(dev_info, dev_info_data.get_mut_ptr());
        break;
      }
    }
  }
  unsafe { SetupDiDestroyDeviceInfoList(dev_info) };
}
