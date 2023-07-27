use std::ptr::null_mut;

use cutils::{check_handle, csizeof, defer, strings::WideCStr, unsafe_defer};
use winapi::{
  shared::{
    devguid::GUID_DEVCLASS_NET,
    minwindef::{FALSE, HINSTANCE},
    ntdef::LPCSTR,
    windef::HWND,
    winerror::ERROR_SUCCESS,
  },
  um::{
    errhandlingapi::{GetLastError, SetLastError},
    processenv::GetCommandLineW,
    setupapi::{
      SetupDiCallClassInstaller, SetupDiCreateDeviceInfoListExW, SetupDiDestroyDeviceInfoList,
      SetupDiOpenDeviceInfoW, SetupDiSetClassInstallParamsW, DICS_DISABLE, DICS_ENABLE,
      DICS_FLAG_GLOBAL, DIF_PROPERTYCHANGE, DIF_REMOVE, DIOD_INHERIT_CLASSDRVS,
      DI_REMOVEDEVICE_GLOBAL, SP_CLASSINSTALL_HEADER, SP_DEVINFO_DATA, SP_PROPCHANGE_PARAMS,
      SP_REMOVEDEVICE_PARAMS,
    },
    shellapi::CommandLineToArgvW,
    winbase::LocalFree,
  },
};

fn write_formatted(handle: u32, msg: &WideCStr) {
  let mut msg_size = msg.sizeof();
  unsafe {
    winapi::um::fileapi::WriteFile(
      winapi::um::processenv::GetStdHandle(handle),
      msg.as_ptr().cast(),
      msg_size,
      &mut msg_size,
      null_mut(),
    );
  }
}

macro_rules! error {
  ($fmt:literal $(,$args:expr)*) => {
    let msg = cutils::widecstring!("{}", format_args!(concat!("!", $fmt) $(,$args)*));
    write_formatted(winapi::um::winbase::STD_ERROR_HANDLE, &msg);
  };
}
macro_rules! info {
  ($fmt:literal $(,$args:expr)*) => {
    let msg = cutils::widecstring!("{}", format_args!(concat!("+", $fmt) $(,$args)*));
    write_formatted(winapi::um::winbase::STD_ERROR_HANDLE, &msg);
  };
}
#[allow(unused_macros)]
macro_rules! warn {
  ($fmt:literal $(,$args:expr)*) => {
    let msg = cutils::widecstring!("{}", format_args!(concat!("-", $fmt) $(,$args)*));
    write_formatted(winapi::um::winbase::STD_ERROR_HANDLE, &msg);
  };
}
macro_rules! owrite {
  ($fmt:literal $(,$args:expr)*) => {
    let msg = cutils::widecstring!($fmt $(,$args)*);
    write_formatted(winapi::um::winbase::STD_OUTPUT_HANDLE, &msg);
  };
}

fn set_no_error() {
  unsafe { SetLastError(ERROR_SUCCESS) };
}

fn print_last_error() {
  owrite!("{:08x}", unsafe { GetLastError() });
}

#[no_mangle]
pub unsafe extern "system" fn RemoveInstance(_: HWND, _: HINSTANCE, _: LPCSTR, _: i32) {
  let mut argc = 0;
  let argvp = CommandLineToArgvW(GetCommandLineW(), &mut argc);
  unsafe_defer! { cleanup <-
    LocalFree(argvp.cast());
  }
  set_no_error();
  if argc < 3 {
    error!("Invalid arguments.");
    return;
  }
  defer! {
    print_last_error();
  }
  let argv = std::slice::from_raw_parts(argvp, argc as usize);
  let instance_id = argv[2];
  info!(
    "Removing instance: {}",
    WideCStr::from_ptr(instance_id).display()
  );
  let dev_info =
    SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, null_mut(), null_mut(), null_mut());
  if !check_handle(dev_info) {
    error!("Failed to create dev info");
    return;
  }
  unsafe_defer! { cleanup_dev_info <-
    SetupDiDestroyDeviceInfoList(dev_info);
  };
  let mut dev_info_data = SP_DEVINFO_DATA {
    cbSize: csizeof!(SP_DEVINFO_DATA),
    ..unsafe { std::mem::zeroed() }
  };
  if FALSE
    == SetupDiOpenDeviceInfoW(
      dev_info,
      instance_id,
      null_mut(),
      DIOD_INHERIT_CLASSDRVS,
      &mut dev_info_data,
    )
  {
    error!("Failed to open device info");
    return;
  }
  let mut remove_device_params = SP_REMOVEDEVICE_PARAMS {
    ClassInstallHeader: SP_CLASSINSTALL_HEADER {
      cbSize: csizeof!(SP_CLASSINSTALL_HEADER),
      InstallFunction: DIF_REMOVE,
    },
    Scope: DI_REMOVEDEVICE_GLOBAL,
    HwProfile: 0,
  };
  if FALSE
    == SetupDiSetClassInstallParamsW(
      dev_info,
      &mut dev_info_data,
      &mut remove_device_params.ClassInstallHeader,
      csizeof!(=remove_device_params),
    )
    || FALSE == SetupDiCallClassInstaller(DIF_REMOVE, dev_info, &mut dev_info_data)
  {
    return;
  }
  cleanup_dev_info.run();
  cleanup.run();
}

#[no_mangle]
pub unsafe extern "system" fn EnableInstance(_: HWND, _: HINSTANCE, _: LPCSTR, _: i32) {
  let mut argc = 0;
  let argvp = CommandLineToArgvW(GetCommandLineW(), &mut argc);
  unsafe_defer! { cleanup <-
    LocalFree(argvp.cast());
  }
  set_no_error();
  if argc < 3 {
    error!("Invalid arguments.");
    return;
  }
  defer! {
    print_last_error();
  }
  let argv = std::slice::from_raw_parts(argvp, argc as usize);
  let instance_id = argv[2];
  let dev_info =
    SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, null_mut(), null_mut(), null_mut());
  if !check_handle(dev_info) {
    error!("Failed to create device info list");
    return;
  }
  unsafe_defer! { cleanup_dev_info <-
    SetupDiDestroyDeviceInfoList(dev_info);
  };
  let mut dev_info_data = SP_DEVINFO_DATA {
    cbSize: csizeof!(SP_DEVINFO_DATA),
    ..unsafe { std::mem::zeroed() }
  };
  if FALSE
    == SetupDiOpenDeviceInfoW(
      dev_info,
      instance_id,
      null_mut(),
      DIOD_INHERIT_CLASSDRVS,
      &mut dev_info_data,
    )
  {
    error!("Failed to open device info");
    return;
  }
  let mut params = SP_PROPCHANGE_PARAMS {
    ClassInstallHeader: SP_CLASSINSTALL_HEADER {
      cbSize: csizeof!(SP_CLASSINSTALL_HEADER),
      InstallFunction: DIF_PROPERTYCHANGE,
    },
    StateChange: DICS_ENABLE,
    Scope: DICS_FLAG_GLOBAL,
    HwProfile: 0,
  };
  if FALSE
    == SetupDiSetClassInstallParamsW(
      dev_info,
      &mut dev_info_data,
      &mut params.ClassInstallHeader,
      csizeof!(=params),
    )
    || FALSE == SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, dev_info, &mut dev_info_data)
  {
    error!("Failed to enable instance");
    return;
  }
  cleanup_dev_info.run();
  cleanup.run();
}

#[no_mangle]
pub unsafe extern "system" fn DisableInstance(_: HWND, _: HINSTANCE, _: LPCSTR, _: i32) {
  let mut argc = 0;
  let argvp = CommandLineToArgvW(GetCommandLineW(), &mut argc);
  unsafe_defer! { cleanup <-
    LocalFree(argvp.cast());
  }
  set_no_error();
  if argc < 3 {
    error!("Invalid arguments.");
    return;
  }
  defer! {
    print_last_error();
  }
  let argv = std::slice::from_raw_parts(argvp, argc as usize);
  let instance_id = argv[2];
  let dev_info =
    SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, null_mut(), null_mut(), null_mut());
  if !check_handle(dev_info) {
    error!("Failed to create device info list");
    return;
  }
  unsafe_defer! { cleanup_dev_info <-
    SetupDiDestroyDeviceInfoList(dev_info);
  };
  let mut dev_info_data = SP_DEVINFO_DATA {
    cbSize: csizeof!(SP_DEVINFO_DATA),
    ..unsafe { std::mem::zeroed() }
  };
  if FALSE
    == SetupDiOpenDeviceInfoW(
      dev_info,
      instance_id,
      null_mut(),
      DIOD_INHERIT_CLASSDRVS,
      &mut dev_info_data,
    )
  {
    error!("Failed to open device info");
    return;
  }
  let mut params = SP_PROPCHANGE_PARAMS {
    ClassInstallHeader: SP_CLASSINSTALL_HEADER {
      cbSize: csizeof!(SP_CLASSINSTALL_HEADER),
      InstallFunction: DIF_PROPERTYCHANGE,
    },
    StateChange: DICS_DISABLE,
    Scope: DICS_FLAG_GLOBAL,
    HwProfile: 0,
  };
  if FALSE
    == SetupDiSetClassInstallParamsW(
      dev_info,
      &mut dev_info_data,
      &mut params.ClassInstallHeader,
      csizeof!(=params),
    )
    || FALSE == SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, dev_info, &mut dev_info_data)
  {
    error!("Failed to enable instance");
    return;
  }
  cleanup_dev_info.run();
  cleanup.run();
}

#[cfg(feature = "windows7")]
#[no_mangle]
pub unsafe extern "system" fn CreateInstanceWin7(_: HWND, _: HINSTANCE, _: LPCSTR, _: i32) {
  use cutils::{static_widecstr, strings::StaticWideCStr};
  use winapi::{
    shared::minwindef::TRUE,
    um::{
      cfgmgr32::MAX_DEVICE_ID_LEN,
      setupapi::{
        SetupDiBuildDriverInfoList, SetupDiDestroyDriverInfoList, SetupDiEnumDriverInfoW,
        SetupDiGetDeviceInstallParamsW, SetupDiGetDeviceInstanceIdW,
        SetupDiSetDeviceInstallParamsW, SetupDiSetDeviceRegistryPropertyW,
        SetupDiSetSelectedDevice, SetupDiSetSelectedDriverW, DIF_INSTALLDEVICE,
        DIF_INSTALLINTERFACES, DIF_REGISTERDEVICE, DIF_REGISTER_COINSTALLERS, DI_QUIETINSTALL,
        SPDIT_COMPATDRIVER, SPDRP_HARDWAREID, SP_DEVINSTALL_PARAMS_W, SP_DRVINFO_DATA_W,
      },
    },
  };
  set_no_error();
  let mut instance_id = StaticWideCStr::<MAX_DEVICE_ID_LEN>::zeroed();
  unsafe_defer! { cleanup <-
    owrite!("{:08x} {}", GetLastError(), "\"\"");
  }
  let dev_info =
    SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, null_mut(), null_mut(), null_mut());
  if !check_handle(dev_info) {
    return;
  }
  unsafe_defer! { cleanup_dev_info <-
    SetupDiDestroyDeviceInfoList(dev_info);
  };
  let mut dev_info_data = SP_DEVINFO_DATA {
    cbSize: csizeof!(SP_DEVINFO_DATA),
    ..unsafe { std::mem::zeroed() }
  };
  let mut dev_install_params = SP_DEVINSTALL_PARAMS_W {
    cbSize: csizeof!(SP_DEVINSTALL_PARAMS_W),
    ..unsafe { std::mem::zeroed() }
  };
  let dev_info_data_ptr: *mut _ = &mut dev_info_data;
  if FALSE == SetupDiGetDeviceInstallParamsW(dev_info, dev_info_data_ptr, &mut dev_install_params) {
    return;
  }
  dev_install_params.Flags |= DI_QUIETINSTALL;
  if FALSE == SetupDiSetDeviceInstallParamsW(dev_info, dev_info_data_ptr, &mut dev_install_params) {
    return;
  }
  if FALSE == SetupDiSetSelectedDevice(dev_info, dev_info_data_ptr) {
    return;
  }
  let hwids = static_widecstr!("Wintun"; 8);
  if FALSE
    == SetupDiSetDeviceRegistryPropertyW(
      dev_info,
      dev_info_data_ptr,
      SPDRP_HARDWAREID,
      hwids.as_ptr().cast(),
      hwids.sizeof(),
    )
  {
    return;
  }
  if FALSE == SetupDiBuildDriverInfoList(dev_info, dev_info_data_ptr, SPDIT_COMPATDRIVER) {
    return;
  }
  unsafe_defer! { cleaunp_driver_info <-
    SetupDiDestroyDriverInfoList(dev_info, dev_info_data_ptr, SPDIT_COMPATDRIVER);
  };
  let mut drv_info_data = SP_DRVINFO_DATA_W {
    cbSize: csizeof!(SP_DRVINFO_DATA_W),
    ..unsafe { std::mem::zeroed() }
  };
  if FALSE
    == SetupDiEnumDriverInfoW(
      dev_info,
      dev_info_data_ptr,
      SPDIT_COMPATDRIVER,
      0,
      &mut drv_info_data,
    )
    || FALSE == SetupDiSetSelectedDriverW(dev_info, &mut dev_info_data, &mut drv_info_data)
  {
    return;
  }
  if FALSE == SetupDiCallClassInstaller(DIF_REGISTERDEVICE, dev_info, dev_info_data_ptr) {
    return;
    // goto cleanup_dev_info ?
  }
  SetupDiCallClassInstaller(DIF_REGISTER_COINSTALLERS, dev_info, dev_info_data_ptr);
  SetupDiCallClassInstaller(DIF_INSTALLINTERFACES, dev_info, dev_info_data_ptr);
  unsafe_defer! { cleanup_device <-
    let mut remove_device_params = SP_REMOVEDEVICE_PARAMS {
      ClassInstallHeader: SP_CLASSINSTALL_HEADER {
        cbSize: csizeof!(SP_CLASSINSTALL_HEADER),
        InstallFunction: DIF_REMOVE,
      },
      Scope: DI_REMOVEDEVICE_GLOBAL,
      HwProfile: 0,
    };
    if TRUE
      == SetupDiSetClassInstallParamsW(
        dev_info,
        &mut dev_info_data,
        &mut remove_device_params.ClassInstallHeader,
        csizeof!(=remove_device_params),
      )
    {
      SetupDiCallClassInstaller(DIF_REMOVE, dev_info, &mut dev_info_data);
    }
  };
  if FALSE == SetupDiCallClassInstaller(DIF_INSTALLDEVICE, dev_info, dev_info_data_ptr) {
    return;
  }
  let mut required_chars = instance_id.capacity();
  if FALSE
    == SetupDiGetDeviceInstanceIdW(
      dev_info,
      dev_info_data_ptr,
      instance_id.as_mut_ptr(),
      required_chars,
      &mut required_chars,
    )
  {
    return;
  }
  cleanup_device.forget();
  cleaunp_driver_info.run();
  cleanup_dev_info.run();
  cleanup.forget();
  owrite!("{:08x} {}", ERROR_SUCCESS, instance_id.display());
}
