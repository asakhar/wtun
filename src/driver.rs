use get_last_error::Win32Error;
use widestring::{widecstr, WideCStr, WideCString};
use winapi::{
  shared::{
    cfg::{CM_PROB_DISABLED, DN_HAS_PROBLEM},
    devguid::GUID_DEVCLASS_NET,
    devpropdef::DEVPROPTYPE,
    minwindef::{BYTE, DWORD, FALSE, FILETIME, UINT},
    ntdef::{DWORDLONG, NT_SUCCESS, PVOID, WCHAR},
    ntstatus::STATUS_INFO_LENGTH_MISMATCH,
    winerror::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_VERSION_PARSE_ERROR},
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
    AdapterCleanupOrphanedDevices, AdapterDisableInstance, AdapterEnableInstance,
    DEVPKEY_Wintun_Name,
  },
  error, info, last_error, log,
  namespace::SystemNamedMutexLock,
  ntdll::{SystemModuleInformation, PRTL_PROCESS_MODULES},
  resource::{copy_to_file, create_temp_dir, ResId},
  utils::{
    check_handle, set_last_error, CastToMutVoidPtrExt, Defered, GetPtrExt, InitZeroed, Win32Result,
  },
  warn, wide_array,
  winapi_ext::{
    shlwapi::PathFindFileNameW,
    verrsrc::VS_FIXEDFILEINFO,
    winternl::{NtQuerySystemInformation, RtlNtStatusToDosError},
  },
  wintun_inf::{WINTUN_INF_FILETIME, WINTUN_INF_VERSION},
  WINTUN_ENUMERATOR,
};

use std::collections::LinkedList;

pub const WINTUN_HWID: &WideCStr = widecstr!("Wintun");

pub type SP_DEVINFO_DATA_LIST = LinkedList<SP_DEVINFO_DATA>;

fn DisableAllOurAdapters(
  DevInfo: HDEVINFO,
  DisabledAdapters: &mut SP_DEVINFO_DATA_LIST,
) -> Win32Result<()> {
  let mut overall_result = Ok(());
  for EnumIndex in 0.. {
    let mut device = SP_DEVINFO_DATA {
      cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as DWORD,
      ..unsafe { InitZeroed::init_zeroed() }
    };
    let result = unsafe { SetupDiEnumDeviceInfo(DevInfo, EnumIndex, device.get_mut_ptr()) };
    if result == FALSE {
      let error = Win32Error::get_last_error();
      if error.code() == ERROR_NO_MORE_ITEMS {
        break;
      }
      if overall_result.is_ok() {
        overall_result = Err(error);
      }
      continue;
    }
    let prop_type = unsafe { DEVPROPTYPE::init_zeroed() };
    let mut name = wide_array![b"<unknown>"; MAX_ADAPTER_NAME];
    unsafe {
      SetupDiGetDevicePropertyW(
        DevInfo,
        device.get_mut_ptr(),
        DEVPKEY_Wintun_Name.get_const_ptr(),
        prop_type.get_mut_ptr(),
        name.as_ptr() as *mut _,
        std::mem::size_of_val(&name) as DWORD,
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
    let name = unsafe { WideCStr::from_ptr_str(name.as_ptr()) };
    log!(
      crate::logger::LogLevel::Info,
      "Disabling adapter \"{}\"",
      name.display()
    );
    if let Err(err) = AdapterDisableInstance(DevInfo, device.get_mut_ptr()) {
      error!(err, "Failed to disable adapter \"{}\"", name.display());
      if overall_result.is_ok() {
        overall_result = Err(err);
      }
      continue;
    }
    DisabledAdapters.push_back(device);
  }
  overall_result
}

fn EnableAllOurAdapters(
  DevInfo: HDEVINFO,
  AdaptersToEnable: &mut SP_DEVINFO_DATA_LIST,
) -> Win32Result<()> {
  let mut overall_result = Ok(());
  for device in AdaptersToEnable {
    let prop_type = unsafe { DEVPROPTYPE::init_zeroed() };
    let mut name = wide_array![b"<unknown>"; MAX_ADAPTER_NAME];
    unsafe {
      SetupDiGetDevicePropertyW(
        DevInfo,
        device.get_mut_ptr(),
        DEVPKEY_Wintun_Name.get_const_ptr(),
        prop_type.get_mut_ptr(),
        name.as_ptr() as *mut _,
        std::mem::size_of_val(&name) as DWORD,
        std::ptr::null_mut(),
        0,
      )
    };
    let name = unsafe { WideCStr::from_ptr_str(name.as_ptr()) };
    info!("Enabling adapter: \"{}\"", name.display());
    if let Err(err) = AdapterEnableInstance(DevInfo, device.get_mut_ptr()) {
      error!(err, "Failed to enable adapter \"{}\"", name.display());
      if overall_result.is_ok() {
        overall_result = Err(err);
      }
    }
  }
  overall_result
}

fn IsNewer(
  DriverDate1: &FILETIME,
  DriverVersion1: DWORDLONG,
  DriverDate2: &FILETIME,
  DriverVersion2: DWORDLONG,
) -> bool {
  if DriverDate1.dwHighDateTime > DriverDate2.dwHighDateTime {
    return true;
  }
  if DriverDate1.dwHighDateTime < DriverDate2.dwHighDateTime {
    return false;
  }

  if DriverDate1.dwLowDateTime > DriverDate2.dwLowDateTime {
    return true;
  }
  if DriverDate1.dwLowDateTime < DriverDate2.dwLowDateTime {
    return false;
  }

  if DriverVersion1 > DriverVersion2 {
    return true;
  }
  if DriverVersion1 < DriverVersion2 {
    return false;
  }

  false
}

fn VersionOfFile(filename: &WideCStr) -> Win32Result<DWORD> {
  let zero = 0;
  let len = unsafe { GetFileVersionInfoSizeW(filename.as_ptr(), zero.get_mut_ptr()) };
  if len == 0 {
    return Err(last_error!(
      "Failed to query {} version info size",
      filename.display()
    ));
  }

  let mut version_info = vec![0u8; len as usize];
  let mut version = 0;
  let mut fixed_info = std::ptr::null_mut();
  let fixed_info_len = std::mem::size_of::<VS_FIXEDFILEINFO>() as UINT;
  if unsafe {
    GetFileVersionInfoW(
      filename.as_ptr(),
      0,
      len,
      version_info.as_mut_ptr().cast_to_pvoid(),
    )
  } == FALSE
  {
    return Err(last_error!(
      "Failed to get {} version info",
      filename.display()
    ));
  }
  if unsafe {
    VerQueryValueW(
      version_info.as_ptr() as PVOID,
      widecstr!("\\").as_ptr(),
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
  let fixed_info = unsafe { &mut *(fixed_info as *mut VS_FIXEDFILEINFO) };
  version = fixed_info.dwFileVersionMS;
  if version == 0 {
    let error = Win32Error::new(ERROR_VERSION_PARSE_ERROR);
    set_last_error(error);
    log!(
      crate::logger::LogLevel::Warning,
      "Determined version of {}, but was v0.0, so returning failure",
      filename.display()
    );
    return Err(error);
  }
  Ok(version)
}

fn MaybeGetRunningDriverVersion(ReturnOneIfRunningInsteadOfVersion: bool) -> Win32Result<DWORD> {
  let mut buffer_size: DWORD = 128 * 1024;
  let mut modules_buf = vec![0u64; (buffer_size / 8) as usize];
  loop {
    let status = unsafe {
      NtQuerySystemInformation(
        SystemModuleInformation,
        modules_buf.as_mut_ptr().cast_to_pvoid(),
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
    set_last_error(Win32Error::new(unsafe { RtlNtStatusToDosError(status) }));
    return Err(last_error!("Failed to enumerate drivers"));
  }
  let modules = unsafe { &mut *(modules_buf.as_ptr() as PRTL_PROCESS_MODULES) };
  let mut version = 0;
  for i in (1..modules.number()).rev() {
    let module = unsafe { modules.get_mut(i) };
    let Some(nt_filename) = module.filename() else {
      continue;
    };
    if nt_filename.to_str().unwrap_or("") == "wintun.sys" {
      if ReturnOneIfRunningInsteadOfVersion {
        return Ok(1);
      }
      let Some(fullpath) = module.fullpath() else {
        continue;
      };
      let Ok(fullpath) = fullpath.to_str() else {
        continue;
      };
      let Ok(filepath) = WideCString::from_str(&format!("\\\\?\\GLOBALROOT{}", fullpath)) else {
        continue;
      };
      return VersionOfFile(&filepath);
    }
  }
  Err(Win32Error::new(ERROR_FILE_NOT_FOUND))
}

pub fn WintunGetRunningDriverVersion() -> Win32Result<DWORD> {
  MaybeGetRunningDriverVersion(false)
}

pub fn EnsureWintunUnloaded() -> bool {
  let mut loaded = true;
  for tries in 0..1500 {
    if tries == 0 {
      std::thread::sleep(std::time::Duration::from_millis(50));
    }
    loaded = matches!(MaybeGetRunningDriverVersion(true), Ok(v) if v != 0);
    if loaded {
      break;
    }
  }
  !loaded
}

pub fn DriverInstallDeferredCleanup(
  DevInfoExistingAdapters: HDEVINFO,
  ExistingAdapters: &mut SP_DEVINFO_DATA_LIST,
) {
  if !ExistingAdapters.is_empty() {
    EnableAllOurAdapters(DevInfoExistingAdapters, ExistingAdapters);
    ExistingAdapters.clear();
  }
  if check_handle(DevInfoExistingAdapters) {
    unsafe { SetupDiDestroyDeviceInfoList(DevInfoExistingAdapters) };
  }
}

pub fn DriverInstall() -> Win32Result<(HDEVINFO, SP_DEVINFO_DATA_LIST)> {
  let DriverInstallationLock = SystemNamedMutexLock::take_driver_installation_mutex()?;
  let DevInfo = unsafe {
    SetupDiCreateDeviceInfoListExW(
      GUID_DEVCLASS_NET.get_const_ptr(),
      std::ptr::null_mut(),
      std::ptr::null(),
      std::ptr::null_mut(),
    )
  };
  if !check_handle(DevInfo) {
    return Err(last_error!("Failed to create empty device information set"));
  }
  let cleanupDevInfo = Defered::new(|| {
    unsafe { SetupDiDestroyDeviceInfoList(DevInfo) };
  });
  let mut DevInfoData = SP_DEVINFO_DATA {
    cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as DWORD,
    ..unsafe { std::mem::zeroed() }
  };
  let result = unsafe {
    SetupDiCreateDeviceInfoW(
      DevInfo,
      WINTUN_HWID.as_ptr(),
      GUID_DEVCLASS_NET.get_const_ptr(),
      std::ptr::null(),
      std::ptr::null_mut(),
      DICD_GENERATE_ID,
      DevInfoData.get_mut_ptr(),
    )
  };
  if result == FALSE {
    return Err(last_error!(
      "Failed to create new device information element"
    ));
  }
  let hwids = wide_array!(b"Wintun"; 8);
  let result = unsafe {
    SetupDiSetDeviceRegistryPropertyW(
      DevInfo,
      DevInfoData.get_mut_ptr(),
      SPDRP_HARDWAREID,
      hwids.as_ptr() as *const BYTE,
      std::mem::size_of_val(&hwids) as DWORD,
    )
  };
  if result == FALSE {
    return Err(last_error!("Failed to set adapter hardware ID"));
  }
  let result =
    unsafe { SetupDiBuildDriverInfoList(DevInfo, DevInfoData.get_mut_ptr(), SPDIT_COMPATDRIVER) };
  if result == FALSE {
    return Err(last_error!("Failed building adapter driver info list"));
  }
  let cleanupDriverInfoList = Defered::new(|| {
    unsafe { SetupDiDestroyDriverInfoList(DevInfo, DevInfoData.get_mut_ptr(), SPDIT_COMPATDRIVER) };
  });
  let mut driver_date = unsafe { FILETIME::init_zeroed() };
  let mut driver_version = 0;
  let mut dev_info_existing_adapters = INVALID_HANDLE_VALUE;
  let mut existing_adapters = std::collections::LinkedList::new();
  let cleanupExistingAdapters = Defered::new(|| {
    DriverInstallDeferredCleanup(dev_info_existing_adapters, &mut existing_adapters);
  });
  for EnumIndex in 0.. {
    let mut DrvInfoData = SP_DRVINFO_DATA_W {
      cbSize: std::mem::size_of::<SP_DRVINFO_DATA_W>() as DWORD,
      ..unsafe { std::mem::zeroed() }
    };
    let result = unsafe {
      SetupDiEnumDriverInfoW(
        DevInfo,
        DevInfoData.get_mut_ptr(),
        SPDIT_COMPATDRIVER,
        EnumIndex,
        DrvInfoData.get_mut_ptr(),
      )
    };
    if result == FALSE {
      if Win32Error::get_last_error().code() == ERROR_NO_MORE_ITEMS {
        break;
      }
      continue;
    }
    if IsNewer(
      &WINTUN_INF_FILETIME,
      WINTUN_INF_VERSION,
      &DrvInfoData.DriverDate,
      DrvInfoData.DriverVersion,
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
        drop(DisableAllOurAdapters(DevInfo, &mut existing_adapters));
        log!(
          crate::logger::LogLevel::Info,
          "Waiting for existing driver to unload from kernel"
        );
        if !EnsureWintunUnloaded() {
          log!(
            crate::logger::LogLevel::Warning,
            "Failed to unload existing driver, which means a reboot will likely be required"
          );
        }
      }
      log!(
        crate::logger::LogLevel::Info,
        "Removing existing driver {}.{}",
        ((DrvInfoData.DriverVersion & 0xffff000000000000) >> 48),
        ((DrvInfoData.DriverVersion & 0x0000ffff00000000) >> 32)
      );
      let mut large_buffer = [0u8; 0x2000];
      let mut size = std::mem::size_of_val(&large_buffer) as DWORD;
      let drv_into_detail_data_ptr = large_buffer.as_mut_ptr() as *mut SP_DRVINFO_DETAIL_DATA_W;
      let drv_info_detail_data = unsafe { &mut *drv_into_detail_data_ptr };
      drv_info_detail_data.cbSize = std::mem::size_of::<SP_DRVINFO_DETAIL_DATA_W>() as DWORD;
      let result = unsafe {
        SetupDiGetDriverInfoDetailW(
          DevInfo,
          DevInfoData.get_mut_ptr(),
          DrvInfoData.get_mut_ptr(),
          drv_into_detail_data_ptr,
          size,
          size.get_mut_ptr(),
        )
      };
      if result == FALSE {
        warn!("Failed getting adapter driver info detail");
        continue;
      }
      let inf_file_name = unsafe { PathFindFileNameW(drv_info_detail_data.InfFileName.as_ptr()) };
      let result =
        unsafe { SetupUninstallOEMInfW(inf_file_name, SUOI_FORCEDELETE, std::ptr::null_mut()) };
      if result == FALSE {
        let inf_file_name = unsafe { WideCStr::from_ptr_str(inf_file_name) };
        last_error!(
          "Unable to remove existing driver {}",
          inf_file_name.display()
        );
      }
      continue;
    }
    if !IsNewer(
      &DrvInfoData.DriverDate,
      DrvInfoData.DriverVersion,
      &driver_date,
      driver_version,
    ) {
      continue;
    }
    driver_date = DrvInfoData.DriverDate;
    driver_version = DrvInfoData.DriverVersion;
  }
  cleanupDriverInfoList.run();

  if driver_version != 0 {
    info!(
      "Using existing driver {}.{}",
      ((driver_version & 0xffff000000000000) >> 48),
      ((driver_version & 0x0000ffff00000000) >> 32)
    );
    cleanupExistingAdapters.forget();
    return Ok((dev_info_existing_adapters, existing_adapters));
  }
  info!(
    "Installing driver {}.{}",
    ((WINTUN_INF_VERSION & 0xffff000000000000) >> 48),
    ((WINTUN_INF_VERSION & 0x0000ffff00000000) >> 32)
  );
  let random_temp_sub_dir = create_temp_dir()?;
  let cleanupDirectory = Defered::new(|| {
    if let Err(err) = std::fs::remove_dir_all(random_temp_sub_dir) {
      error!(
        Win32Error::new(err.raw_os_error().unwrap() as u32),
        "Failed to remove temp directory"
      );
    }
  });
  let cat_path = random_temp_sub_dir.join("wintun.cat");
  let sys_path = random_temp_sub_dir.join("wintun.sys");
  let inf_path = random_temp_sub_dir.join("wintun.inf");
  info!("Extracting driver");
  let cleanupDelete = Defered::new(|| {
    drop(std::fs::remove_file(&cat_path));
    drop(std::fs::remove_file(&sys_path));
    drop(std::fs::remove_file(&inf_path));
  });
  copy_to_file(&cat_path, ResId::Cat)?;
  copy_to_file(&sys_path, ResId::Sys)?;
  copy_to_file(&inf_path, ResId::Inf)?;
  info!("Installing driver");
  let inf_ptr = WideCString::from_os_str(&inf_path).unwrap();
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
  cleanupExistingAdapters.forget();
  cleanupDevInfo.run();
  DriverInstallationLock.release();
  Ok((dev_info_existing_adapters, existing_adapters))
}

pub fn WintunDeleteDriver() -> Win32Result<()> {
  AdapterCleanupOrphanedDevices();
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
  let cleanupDevInfo = Defered::new(|| {
    unsafe { SetupDiDestroyDeviceInfoList(dev_info) };
  });
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
  let hwids = wide_array!(b"Wintun"; 8);
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
  let cleanupDriverInfoList = Defered::new(|| {
    unsafe {
      SetupDiDestroyDriverInfoList(dev_info, dev_info_data.get_mut_ptr(), SPDIT_COMPATDRIVER)
    };
  });
  for EnumIndex in 0.. {
    let mut drv_info_data = SP_DRVINFO_DATA_W {
      cbSize: std::mem::size_of::<SP_DRVINFO_DATA_W>() as DWORD,
      ..unsafe { std::mem::zeroed() }
    };
    let result = unsafe {
      SetupDiEnumDriverInfoW(
        dev_info,
        dev_info_data.get_mut_ptr(),
        SPDIT_COMPATDRIVER,
        EnumIndex,
        drv_info_data.get_mut_ptr(),
      )
    };
    if result == FALSE {
      if Win32Error::get_last_error().code() == ERROR_NO_MORE_ITEMS {
        break;
      }
      continue;
    }
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
    let inf_file_name_ptr = unsafe { PathFindFileNameW(drv_info_detail_data.InfFileName.as_ptr()) };
    let inf_file_name = unsafe { WideCStr::from_ptr_str(inf_file_name_ptr) };
    info!("Removing driver {}", inf_file_name.display());
    let result =
      unsafe { SetupUninstallOEMInfW(inf_file_name_ptr, 0, std::ptr::null_mut()) };
    if result == FALSE {
      last_error!(
        "Unable to remove driver {}",
        inf_file_name.display()
      );
    }
  }
  cleanupDriverInfoList.run();
  cleanupDevInfo.run();
  driver_installation_lock.release();
  Ok(())
}
