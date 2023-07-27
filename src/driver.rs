use cutils::{
  check_handle, csizeof, defer,
  errors::get_last_error_code,
  inspection::GetPtrExt,
  static_widecstr,
  strings::{WideCStr, WideCString},
  unsafe_defer, wide_array, widecstr, widecstring,
};
use winapi::{
  shared::{
    cfg::{CM_PROB_DISABLED, DN_HAS_PROBLEM},
    devguid::GUID_DEVCLASS_NET,
    devpropdef::DEVPROPTYPE,
    minwindef::{BYTE, DWORD, FALSE, FILETIME, UINT},
    ntdef::{DWORDLONG, NT_SUCCESS, PVOID},
    ntstatus::STATUS_INFO_LENGTH_MISMATCH,
    winerror::{
      ERROR_FILE_NOT_FOUND, ERROR_NOT_SUPPORTED, ERROR_NO_MORE_ITEMS,
      ERROR_VERSION_PARSE_ERROR,
    },
  },
  um::{
    cfgmgr32::{CM_Get_DevNode_Status, CR_SUCCESS},
    handleapi::INVALID_HANDLE_VALUE,
    ipexport::MAX_ADAPTER_NAME,
    setupapi::{
      SetupCopyOEMInfW, SetupDiBuildDriverInfoList, SetupDiCreateDeviceInfoListExW,
      SetupDiCreateDeviceInfoW, SetupDiDestroyDeviceInfoList, SetupDiDestroyDriverInfoList,
      SetupDiEnumDeviceInfo, SetupDiEnumDriverInfoW, SetupDiGetClassDevsExW,
      SetupDiGetDevicePropertyW, SetupDiGetDriverInfoDetailW, SetupDiSetDeviceRegistryPropertyW,
      SetupUninstallOEMInfW, DICD_GENERATE_ID, DIGCF_PRESENT, HDEVINFO, SPDIT_COMPATDRIVER,
      SPDRP_HARDWAREID, SPOST_NONE, SP_DEVINFO_DATA, SP_DRVINFO_DATA_W, SP_DRVINFO_DETAIL_DATA_W,
      SUOI_FORCEDELETE,
    },
    winver::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW},
  },
};

use crate::{
  adapter::{
    adapter_cleanup_orphaned_devices, adapter_disable_instance, adapter_enable_instance,
    DEVPKEY_WINTUN_NAME, WINTUN_ENUMERATOR, WINTUN_HWID,
  },
  logger::{error, info, last_error, log, warn, IntoError},
  namespace::SystemNamedMutexLock,
  ntdll::{SYSTEM_MODULE_INFORMATION, RtlProcessModules},
  resource::{copy_to_file, create_temp_dir, ResId},
  winapi_ext::{
    shlwapi::PathFindFileNameW,
    verrsrc::VS_FIXEDFILEINFO,
    winternl::{NtQuerySystemInformation, RtlNtStatusToDosError},
  },
  wintun_inf::{WINTUN_INF_FILETIME, WINTUN_INF_VERSION},
  wmain::get_system_params,
};

use std::collections::LinkedList;

pub type SpDevinfoDataList = LinkedList<SP_DEVINFO_DATA>;

fn disable_all_our_adapters(
  dev_info: HDEVINFO,
  disabled_adapters: &mut SpDevinfoDataList,
) -> std::io::Result<()> {
  let mut overall_result = Ok(());
  for enum_index in 0.. {
    let mut device = SP_DEVINFO_DATA {
      cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as DWORD,
      ..unsafe { core::mem::zeroed() }
    };
    let result = unsafe { SetupDiEnumDeviceInfo(dev_info, enum_index, device.get_mut_ptr()) };
    if result == FALSE {
      let error = std::io::Error::last_os_error();
      if error.raw_os_error().unwrap() == ERROR_NO_MORE_ITEMS as i32 {
        break;
      }
      if overall_result.is_ok() {
        overall_result = Err(error);
      }
      continue;
    }
    let mut prop_type: DEVPROPTYPE = unsafe { std::mem::zeroed() };
    let mut name = static_widecstr!["<unknown>"; MAX_ADAPTER_NAME];
    unsafe {
      SetupDiGetDevicePropertyW(
        dev_info,
        device.get_mut_ptr(),
        DEVPKEY_WINTUN_NAME.get_const_ptr(),
        prop_type.get_mut_ptr(),
        name.as_mut_ptr().cast(),
        name.capacity(),
        std::ptr::null_mut(),
        0,
      )
    };
    let mut status = 0;
    let mut problem_code = 0;
    let result = unsafe {
      CM_Get_DevNode_Status(
        status.get_mut_ptr(),
        problem_code.get_mut_ptr(),
        device.DevInst,
        0,
      )
    };
    if result != CR_SUCCESS || ((status & DN_HAS_PROBLEM) != 0 && problem_code == CM_PROB_DISABLED)
    {
      continue;
    }
    log!(
      crate::logger::Level::Info,
      "Disabling adapter \"{}\"",
      name.display()
    );
    if let Err(err) = adapter_disable_instance(dev_info, device.get_mut_ptr()) {
      let err = error!(err, "Failed to disable adapter \"{}\"", name.display());
      if overall_result.is_ok() {
        overall_result = Err(err);
      }
      continue;
    }
    disabled_adapters.push_back(device);
  }
  overall_result
}

fn enable_all_our_adapters(
  dev_info: HDEVINFO,
  adapters_to_enable: &mut SpDevinfoDataList,
) -> std::io::Result<()> {
  let mut overall_result = Ok(());
  for device in adapters_to_enable {
    let mut prop_type: DEVPROPTYPE = 0;
    let mut name = static_widecstr!["<unknown>"; MAX_ADAPTER_NAME];
    unsafe {
      SetupDiGetDevicePropertyW(
        dev_info,
        device.get_mut_ptr(),
        DEVPKEY_WINTUN_NAME.get_const_ptr(),
        prop_type.get_mut_ptr(),
        name.as_mut_ptr().cast(),
        name.capacity(),
        std::ptr::null_mut(),
        0,
      )
    };
    info!("Enabling adapter: \"{}\"", name.display());
    if let Err(err) = adapter_enable_instance(dev_info, device.get_mut_ptr()) {
      let err = error!(err, "Failed to enable adapter \"{}\"", name.display());
      if overall_result.is_ok() {
        overall_result = Err(err);
      }
    }
  }
  overall_result
}

fn is_newer(
  driver_date1: &FILETIME,
  driver_version1: DWORDLONG,
  driver_date2: &FILETIME,
  driver_version2: DWORDLONG,
) -> bool {
  if driver_date1.dwHighDateTime > driver_date2.dwHighDateTime {
    return true;
  }
  if driver_date1.dwHighDateTime < driver_date2.dwHighDateTime {
    return false;
  }

  if driver_date1.dwLowDateTime > driver_date2.dwLowDateTime {
    return true;
  }
  if driver_date1.dwLowDateTime < driver_date2.dwLowDateTime {
    return false;
  }

  if driver_version1 > driver_version2 {
    return true;
  }
  if driver_version1 < driver_version2 {
    return false;
  }

  false
}

fn version_of_file(filename: &WideCStr) -> std::io::Result<DWORD> {
  let mut zero = 0;
  let len = unsafe { GetFileVersionInfoSizeW(filename.as_ptr(), zero.get_mut_ptr()) };
  if len == 0 {
    return Err(last_error!(
      "Failed to query {} version info size",
      filename.display()
    ));
  }

  let mut version_info = vec![0u8; len as usize];
  let mut fixed_info = std::ptr::null_mut();
  let mut fixed_info_len = std::mem::size_of::<VS_FIXEDFILEINFO>() as UINT;
  if unsafe { GetFileVersionInfoW(filename.as_ptr(), 0, len, version_info.as_mut_ptr().cast()) }
    == FALSE
  {
    return Err(last_error!(
      "Failed to get {} version info",
      filename.display()
    ));
  }
  if unsafe {
    VerQueryValueW(
      version_info.as_ptr() as PVOID,
      widecstr!(r"\").as_ptr(),
      &mut fixed_info,
      fixed_info_len.get_mut_ptr(),
    )
  } == FALSE
  {
    return Err(last_error!(
      "Failed to get {} version info root",
      filename.display()
    ));
  }
  let fixed_info: &mut VS_FIXEDFILEINFO = unsafe { &mut *(fixed_info.cast()) };
  let version = fixed_info.dwFileVersionMS;
  if version == 0 {
    warn!(
      "Determined version of {}, but was v0.0, so returning failure",
      filename.display()
    );
    return Err(ERROR_VERSION_PARSE_ERROR.into_error());
  }
  Ok(version)
}

fn maybe_get_running_driver_version(
  return_one_if_running_instead_of_version: bool,
) -> std::io::Result<DWORD> {
  let mut buffer_size: DWORD = 128 * 1024;
  let mut modules_buf = vec![0u64; (buffer_size / 8) as usize];
  loop {
    let status = unsafe {
      NtQuerySystemInformation(
        SYSTEM_MODULE_INFORMATION,
        modules_buf.as_mut_ptr().cast(),
        buffer_size,
        buffer_size.get_mut_ptr(),
      )
    };
    if NT_SUCCESS(status) {
      break;
    }
    if status == STATUS_INFO_LENGTH_MISMATCH {
      modules_buf.resize((buffer_size / 8) as usize, 0);
      continue;
    }
    return Err(error!(
      unsafe { RtlNtStatusToDosError(status) },
      "Failed to enumerate drivers"
    ));
  }
  let modules: &mut RtlProcessModules = unsafe { &mut *(modules_buf.as_mut_ptr().cast()) };
  for i in (1..modules.number()).rev() {
    let module = unsafe { modules.get_mut(i) };
    let Some(nt_filename) = module.filename() else {
      continue;
    };
    if nt_filename.to_str().unwrap_or("") == "wintun.sys" {
      if return_one_if_running_instead_of_version {
        return Ok(1);
      }
      let Some(fullpath) = module.fullpath() else {
        continue;
      };
      let Ok(fullpath) = fullpath.to_str() else {
        continue;
      };
      let filepath = widecstring!(r"\\?\GLOBALROOT{}", fullpath);
      return version_of_file(filepath.as_ref());
    }
  }
  Err(std::io::Error::from_raw_os_error(
    ERROR_FILE_NOT_FOUND as i32,
  ))
}

pub fn get_running_driver_version() -> std::io::Result<DWORD> {
  maybe_get_running_driver_version(false)
}

pub fn ensure_wintun_unloaded() -> bool {
  let mut loaded = true;
  for tries in 0..1500 {
    if tries == 0 {
      std::thread::sleep(std::time::Duration::from_millis(50));
    }
    loaded = matches!(maybe_get_running_driver_version(true), Ok(v) if v != 0);
    if loaded {
      break;
    }
  }
  !loaded
}

pub fn driver_install_deferred_cleanup(
  dev_info_existing_adapters: HDEVINFO,
  existing_adapters: &mut SpDevinfoDataList,
) {
  if !existing_adapters.is_empty() {
    drop(enable_all_our_adapters(
      dev_info_existing_adapters,
      existing_adapters,
    ));
    existing_adapters.clear();
  }
  if check_handle(dev_info_existing_adapters) {
    unsafe { SetupDiDestroyDeviceInfoList(dev_info_existing_adapters) };
  }
}

pub fn driver_install() -> std::io::Result<(HDEVINFO, SpDevinfoDataList)> {
  let driver_installation_lock = SystemNamedMutexLock::take_driver_installation_mutex()?;
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

  unsafe_defer! { cleanup_dev_info <- SetupDiDestroyDeviceInfoList(dev_info); };

  let mut dev_info_data = SP_DEVINFO_DATA {
    cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as DWORD,
    ..unsafe { std::mem::zeroed() }
  };
  let result = unsafe {
    SetupDiCreateDeviceInfoW(
      dev_info,
      WINTUN_HWID.as_ptr(),
      GUID_DEVCLASS_NET.get_const_ptr(),
      std::ptr::null(),
      std::ptr::null_mut(),
      DICD_GENERATE_ID,
      dev_info_data.get_mut_ptr(),
    )
  };
  if result == FALSE {
    return Err(last_error!(
      "Failed to create new device information element"
    ));
  }
  let hwids = static_widecstr!("Wintun"; 8);
  let result = unsafe {
    SetupDiSetDeviceRegistryPropertyW(
      dev_info,
      dev_info_data.get_mut_ptr(),
      SPDRP_HARDWAREID,
      hwids.as_ptr().cast(),
      hwids.sizeof(),
    )
  };
  if result == FALSE {
    return Err(last_error!("Failed to set adapter hardware ID"));
  }
  let result =
    unsafe { SetupDiBuildDriverInfoList(dev_info, dev_info_data.get_mut_ptr(), SPDIT_COMPATDRIVER) };
  if result == FALSE {
    return Err(last_error!("Failed building adapter driver info list"));
  }
  let dev_info_data_ptr = dev_info_data.get_mut_ptr();
  unsafe_defer! { cleanup_driver_info_list <- SetupDiDestroyDriverInfoList(dev_info, dev_info_data_ptr, SPDIT_COMPATDRIVER); };
  let mut driver_date: FILETIME = unsafe { std::mem::zeroed() };
  let mut driver_version = 0;
  let mut dev_info_existing_adapters = INVALID_HANDLE_VALUE;
  let dev_info_existing_adapters_ptr = dev_info_existing_adapters.get_mut_ptr();
  let mut existing_adapters = std::collections::LinkedList::new();
  let existing_adapters_ptr = existing_adapters.get_mut_ptr();
  unsafe_defer! { cleanup_existing_adapters <-
    driver_install_deferred_cleanup(*dev_info_existing_adapters_ptr, &mut *existing_adapters_ptr);
  };
  for enum_index in 0.. {
    let mut drv_info_data = SP_DRVINFO_DATA_W {
      cbSize: csizeof!(SP_DRVINFO_DATA_W),
      ..unsafe { std::mem::zeroed() }
    };
    let result = unsafe {
      SetupDiEnumDriverInfoW(
        dev_info,
        dev_info_data.get_mut_ptr(),
        SPDIT_COMPATDRIVER,
        enum_index,
        drv_info_data.get_mut_ptr(),
      )
    };
    if result == FALSE {
      if get_last_error_code() == ERROR_NO_MORE_ITEMS {
        break;
      }
      continue;
    }
    let drv_info_data_driver_date = drv_info_data.DriverDate;
    if is_newer(
      &WINTUN_INF_FILETIME,
      WINTUN_INF_VERSION,
      &drv_info_data_driver_date,
      drv_info_data.DriverVersion,
    ) {
      if !check_handle(dev_info_existing_adapters) {
        dev_info_existing_adapters = unsafe {
          SetupDiGetClassDevsExW(
            GUID_DEVCLASS_NET.get_const_ptr(),
            WINTUN_ENUMERATOR!().as_ptr(),
            std::ptr::null_mut(),
            DIGCF_PRESENT,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
          )
        };
        if !check_handle(dev_info_existing_adapters) {
          return Err(last_error!("Failed to get present adapters"));
        }
        drop(disable_all_our_adapters(dev_info, &mut existing_adapters));
        log!(
          crate::logger::Level::Info,
          "Waiting for existing driver to unload from kernel"
        );
        if !ensure_wintun_unloaded() {
          warn!("Failed to unload existing driver, which means a reboot will likely be required");
        }
      }
      info!(
        "Removing existing driver {}.{}",
        ((drv_info_data.DriverVersion & 0xffff000000000000) >> 48),
        ((drv_info_data.DriverVersion & 0x0000ffff00000000) >> 32)
      );
      let mut large_buffer = [0u8; 0x2000];
      let mut size = std::mem::size_of_val(&large_buffer) as DWORD;
      let drv_into_detail_data_ptr = large_buffer.as_mut_ptr() as *mut SP_DRVINFO_DETAIL_DATA_W;
      let drv_info_detail_data = unsafe { &mut *drv_into_detail_data_ptr };
      drv_info_detail_data.cbSize = std::mem::size_of::<SP_DRVINFO_DETAIL_DATA_W>() as DWORD;
      let result = unsafe {
        SetupDiGetDriverInfoDetailW(
          dev_info,
          dev_info_data.get_mut_ptr(),
          drv_info_data.get_mut_ptr(),
          drv_into_detail_data_ptr,
          size,
          size.get_mut_ptr(),
        )
      };
      if result == FALSE {
        warn!("Failed getting adapter driver info detail");
        continue;
      }
      let inf_file_name = drv_info_detail_data.InfFileName;
      let inf_file_name = unsafe { PathFindFileNameW(inf_file_name.as_ptr()) };
      let result =
        unsafe { SetupUninstallOEMInfW(inf_file_name, SUOI_FORCEDELETE, std::ptr::null_mut()) };
      if result == FALSE {
        let inf_file_name = unsafe { WideCStr::from_ptr(inf_file_name) };
        last_error!(
          "Unable to remove existing driver {}",
          inf_file_name.display()
        );
      }
      continue;
    }
    let drv_info_data_driver_date = drv_info_data.DriverDate;
    if !is_newer(
      &drv_info_data_driver_date,
      drv_info_data.DriverVersion,
      &driver_date,
      driver_version,
    ) {
      continue;
    }
    driver_date = drv_info_data.DriverDate;
    driver_version = drv_info_data.DriverVersion;
  }
  cleanup_driver_info_list.run();

  if driver_version != 0 {
    info!(
      "Using existing driver {}.{}",
      ((driver_version & 0xffff000000000000) >> 48),
      ((driver_version & 0x0000ffff00000000) >> 32)
    );
    cleanup_existing_adapters.forget();
    return Ok((dev_info_existing_adapters, existing_adapters));
  }
  info!(
    "Installing driver {}.{}",
    ((WINTUN_INF_VERSION & 0xffff000000000000) >> 48),
    ((WINTUN_INF_VERSION & 0x0000ffff00000000) >> 32)
  );
  let random_temp_sub_dir = create_temp_dir()?;
  defer! { cleanup_directory <-
    if let Err(err) = std::fs::remove_dir_all(&random_temp_sub_dir) {
      error!(
        err,
        "Failed to remove temp directory"
      );
    }
  }
  let cat_path = random_temp_sub_dir.join("wintun.cat");
  let sys_path = random_temp_sub_dir.join("wintun.sys");
  let inf_path = random_temp_sub_dir.join("wintun.inf");
  info!("Extracting driver");
  defer! { cleanup_delete <-
    drop(std::fs::remove_file(&cat_path));
    drop(std::fs::remove_file(&sys_path));
    drop(std::fs::remove_file(&inf_path));
  };
  let native_machine = unsafe { get_system_params().native_machine };
  let (cat_res_id, sys_res_id, inf_res_id) = match native_machine {
    winapi::um::winnt::IMAGE_FILE_MACHINE_AMD64 => {
      (ResId::CatAmd64, ResId::SysAmd64, ResId::InfAmd64)
    }
    winapi::um::winnt::IMAGE_FILE_MACHINE_ARM64 => {
      (ResId::CatArm64, ResId::SysArm64, ResId::InfArm64)
    }
    winapi::um::winnt::IMAGE_FILE_MACHINE_ARM => (ResId::CatArm, ResId::SysArm, ResId::InfArm),
    winapi::um::winnt::IMAGE_FILE_MACHINE_I386 => (ResId::CatX86, ResId::SysX86, ResId::InfX86),
    _ => {
      return Err(error!(
        ERROR_NOT_SUPPORTED,
        "Unsupported platform 0x{:x}", native_machine
      ))
    }
  };
  copy_to_file(&cat_path, cat_res_id)?;
  copy_to_file(&sys_path, sys_res_id)?;
  copy_to_file(&inf_path, inf_res_id)?;
  info!("Installing driver");
  let inf_ptr = WideCString::from(inf_path.as_os_str());
  let result = unsafe {
    SetupCopyOEMInfW(
      inf_ptr.as_ptr(),
      std::ptr::null(),
      SPOST_NONE,
      0,
      std::ptr::null_mut(),
      0,
      std::ptr::null_mut(),
      std::ptr::null_mut(),
    )
  };
  if result == FALSE {
    last_error!("Could not install driver {} to store", inf_path.display());
  }
  cleanup_delete.run();
  cleanup_directory.run();
  cleanup_existing_adapters.forget();
  cleanup_dev_info.run();
  driver_installation_lock.release();
  Ok((dev_info_existing_adapters, existing_adapters))
}

pub fn wintun_delete_driver() -> std::io::Result<()> {
  adapter_cleanup_orphaned_devices();
  let driver_installation_lock = SystemNamedMutexLock::take_driver_installation_mutex()?;
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
  unsafe_defer! { cleanup_dev_info <- SetupDiDestroyDeviceInfoList(dev_info); };
  let mut dev_info_data = SP_DEVINFO_DATA {
    cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as DWORD,
    ..unsafe { std::mem::zeroed() }
  };
  let result = unsafe {
    SetupDiCreateDeviceInfoW(
      dev_info,
      WINTUN_HWID.as_ptr(),
      GUID_DEVCLASS_NET.get_const_ptr(),
      std::ptr::null(),
      std::ptr::null_mut(),
      DICD_GENERATE_ID,
      dev_info_data.get_mut_ptr(),
    )
  };
  if result == FALSE {
    return Err(last_error!(
      "Failed to create new device information element"
    ));
  }
  let hwids = wide_array!("Wintun"; 8);
  let result = unsafe {
    SetupDiSetDeviceRegistryPropertyW(
      dev_info,
      dev_info_data.get_mut_ptr(),
      SPDRP_HARDWAREID,
      hwids.as_ptr() as *const BYTE,
      std::mem::size_of_val(&hwids) as DWORD,
    )
  };
  if result == FALSE {
    return Err(last_error!("Failed to set adapter hardware ID"));
  }
  let result = unsafe {
    SetupDiBuildDriverInfoList(dev_info, dev_info_data.get_mut_ptr(), SPDIT_COMPATDRIVER)
  };
  if result == FALSE {
    return Err(last_error!("Failed building adapter driver info list"));
  }
  let dev_info_data_ptr = dev_info_data.get_mut_ptr();
  unsafe_defer! { cleanup_driver_info_list <-
    SetupDiDestroyDriverInfoList(dev_info, dev_info_data_ptr, SPDIT_COMPATDRIVER);
  };
  for enum_index in 0.. {
    let mut drv_info_data = SP_DRVINFO_DATA_W {
      cbSize: std::mem::size_of::<SP_DRVINFO_DATA_W>() as DWORD,
      ..unsafe { std::mem::zeroed() }
    };
    let result = unsafe {
      SetupDiEnumDriverInfoW(
        dev_info,
        dev_info_data_ptr,
        SPDIT_COMPATDRIVER,
        enum_index,
        drv_info_data.get_mut_ptr(),
      )
    };
    if result == FALSE {
      if get_last_error_code() == ERROR_NO_MORE_ITEMS {
        break;
      }
      continue;
    }
    let mut large_buffer = [0u64; 0x2000/8];
    let mut size = csizeof!(=large_buffer);
    let drv_into_detail_data_ptr = large_buffer.as_mut_ptr() as *mut SP_DRVINFO_DETAIL_DATA_W;
    let drv_info_detail_data = unsafe { &mut *drv_into_detail_data_ptr };
    drv_info_detail_data.cbSize = std::mem::size_of::<SP_DRVINFO_DETAIL_DATA_W>() as DWORD;
    let result = unsafe {
      SetupDiGetDriverInfoDetailW(
        dev_info,
        dev_info_data.get_mut_ptr(),
        drv_info_data.get_mut_ptr(),
        drv_into_detail_data_ptr,
        size,
        size.get_mut_ptr(),
      )
    };
    if result == FALSE {
      warn!("Failed getting adapter driver info detail");
      continue;
    }
    let inf_file_name = drv_info_detail_data.InfFileName;
    let inf_file_name_ptr = unsafe { PathFindFileNameW(inf_file_name.as_ptr()) };
    let inf_file_name = unsafe { WideCStr::from_ptr(inf_file_name_ptr) };
    info!("Removing driver {}", inf_file_name.display());
    let result = unsafe { SetupUninstallOEMInfW(inf_file_name_ptr, 0, std::ptr::null_mut()) };
    if result == FALSE {
      last_error!("Unable to remove driver {}", inf_file_name.display());
    }
  }
  cleanup_driver_info_list.run();
  cleanup_dev_info.run();
  driver_installation_lock.release();
  Ok(())
}
