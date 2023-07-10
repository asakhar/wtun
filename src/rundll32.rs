use std::io::{BufRead, Read};

use cutils::{
  defer,
  files::get_windows_dir_path,
  inspection::GetPtrExt,
  strings::{StaticWideCStr, WideCStr},
};
use get_last_error::Win32Error;
use winapi::{
  shared::{
    minwindef::FALSE,
    winerror::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, ERROR_SUCCESS},
  },
  um::{
    cfgmgr32::MAX_DEVICE_ID_LEN,
    setupapi::{SetupDiGetDeviceInstanceIdW, HDEVINFO, SP_DEVINFO_DATA},
  },
};

use crate::{
  logger::{error, info, last_error},
  resource::{self, create_temp_dir, ResId},
  wmain::get_system_params,
};

pub(crate) fn remove_instance(
  dev_info: HDEVINFO,
  dev_info_data: *mut SP_DEVINFO_DATA,
) -> std::io::Result<()> {
  invoke_class_installer("remove", "RemoveInstance", dev_info, dev_info_data)
}
pub(crate) fn enable_instance(
  dev_info: HDEVINFO,
  dev_info_data: *mut SP_DEVINFO_DATA,
) -> std::io::Result<()> {
  invoke_class_installer("enable", "EnableInstance", dev_info, dev_info_data)
}
pub(crate) fn disable_instance(
  dev_info: HDEVINFO,
  dev_info_data: *mut SP_DEVINFO_DATA,
) -> std::io::Result<()> {
  invoke_class_installer("disable", "DisableInstance", dev_info, dev_info_data)
}
pub(crate) fn create_instance(
  instance_id: &mut WideCStr,
) -> std::io::Result<StaticWideCStr<MAX_DEVICE_ID_LEN>> {
  info!("Spawning native process to create instance");
  let response = match execute_rundll32("CreateInstanceWin7", std::iter::empty()) {
    Ok(res) => res,
    Err(err) => return Err(error!(err, "Error executing worker process")),
  };
  let error_bytes: [u8; 4] = response.try_into().ok().ok_or(error!(
    ERROR_INVALID_PARAMETER,
    "Incomplete response: {:?}", response
  ))?;
  let error = u32::from_be_bytes(error_bytes);
  if error != ERROR_SUCCESS {
    return Err(std::io::Error::from_raw_os_error(error as i32));
  }
  use std::str::from_utf8;
  from_utf8(&response[4..]).ok().map(StaticWideCStr::<MAX_DEVICE_ID_LEN>::encode).flatten().ok_or(error!(
    ERROR_INVALID_PARAMETER,
    "Invalid response: {:?}", response
  ))
}
fn execute_rundll32<'a>(
  function: &str,
  arguments: impl Iterator<Item = &'a str>,
) -> std::io::Result<Vec<u8>> {
  let windows_dir_path = match get_windows_dir_path() {
    Ok(res) => res,
    Err(err) => return Err(error!(err, "Failed to get Windows folder")),
  };
  let rundll32_path = windows_dir_path.join(r"Sysnative\rundll32.exe");
  let random_temp_subdir = match create_temp_dir() {
    Ok(res) => res,
    Err(err) => return Err(error!(err, "Failed to create temporary folder")),
  };
  defer! { cleanupDirectory <-
    drop(std::fs::remove_dir_all(random_temp_subdir));
  };
  let dll_path = random_temp_subdir.join("setupapihost.dll");
  let native_machine = unsafe { get_system_params().NativeMachine };
  let resource_id = match native_machine {
    IMAGE_FILE_MACHINE_AMD64 => ResId::SetupApiHostAmd64,
    IMAGE_FILE_MACHINE_ARM64 => ResId::SetupApiHostArm64,
    _ => {
      return Err(error!(
        Win32Error::new(ERROR_NOT_SUPPORTED),
        "Unsupported platform 0x{:x}", native_machine
      ))
    }
  };
  defer! { cleanupDelete <-
    drop(std::fs::remove_file(dll_path));
  };
  if let Err(err) = resource::copy_to_file(&dll_path, resource_id) {
    return Err(error!(
      err,
      "Failed to copy resource {:?} to {}",
      resource_id,
      dll_path.display()
    ));
  }
  let mut proc = match std::process::Command::new(rundll32_path)
    .args(
      [format!("{},{}", dll_path.display(), function).as_str()]
        .into_iter()
        .chain(arguments),
    )
    .stderr(std::process::Stdio::piped())
    .stdout(std::process::Stdio::piped())
    .spawn()
  {
    Ok(res) => res,
    Err(err) => {
      let err = err
        .raw_os_error()
        .map(|e| e as u32)
        .unwrap_or(ERROR_ACCESS_DENIED);
      return Err(error!(err, "Failed to create process"));
    }
  };
  let stderr = proc.stderr.take().unwrap();
  let mut stderr = std::io::BufReader::new(stderr);
  let mut read_log = || -> std::io::Result<()> {
    let mut buf = [0; 1];
    stderr.read_exact(&mut buf)?;
    let level = match buf[0] {
      b'+' => crate::logger::LogLevel::Info,
      b'-' => crate::logger::LogLevel::Warning,
      b'!' => crate::logger::LogLevel::Error,
    };
    let mut buf = [0; 8];
    stderr.read_exact(&mut buf)?;
    let secs = u64::from_be_bytes(buf);
    let mut buf = [0; 4];
    stderr.read_exact(&mut buf)?;
    let nanos = u32::from_be_bytes(buf);
    let time = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::new(secs, nanos);
    let mut buf = String::new();
    stderr.read_line(&mut buf)?;
    crate::logger::WINTUN_LOGGER.log_with_time(level, time, format_args!("{}", buf));
    Ok(())
  };
  while read_log().is_ok() {}
  let output = match proc.wait_with_output() {
    Ok(res) => res,
    Err(err) => {
      let err = err
        .raw_os_error()
        .map(|e| e as u32)
        .unwrap_or(ERROR_ACCESS_DENIED);
      return Err(error!(err, "Failed to create process"));
    }
  };

  cleanupDelete.run();
  cleanupDirectory.run();
  Ok(output.stdout)
}

fn invoke_class_installer(
  action: &str,
  function: &str,
  dev_info: HDEVINFO,
  dev_info_data: *mut SP_DEVINFO_DATA,
) -> std::io::Result<()> {
  info!("Spawning native process to {} instance", action);
  let mut instance_id = StaticWideCStr::<MAX_DEVICE_ID_LEN>::zeroed();
  let mut required_chars = MAX_DEVICE_ID_LEN as u32;
  if FALSE
    == unsafe {
      SetupDiGetDeviceInstanceIdW(
        dev_info,
        dev_info_data,
        instance_id.as_mut_ptr(),
        required_chars,
        required_chars.get_mut_ptr(),
      )
    }
  {
    return Err(last_error!("Failed to get adapter instance ID"));
  }
  let instance_id = instance_id.display().to_string();
  let response = match execute_rundll32(function, std::iter::once(instance_id.as_str())) {
    Ok(res) => res,
    Err(err) => {
      return Err(error!(
        err,
        "Error executing worker process: {}", instance_id
      ))
    }
  };
  let error_bytes: [u8; 4] = response.try_into().ok().ok_or(error!(
    ERROR_INVALID_PARAMETER,
    "Incomplete response: {:?}", response
  ))?;
  let error = u32::from_be_bytes(error_bytes);
  if error != ERROR_SUCCESS {
    Err(std::io::Error::from_raw_os_error(error as i32))
  } else {
    Ok(())
  }
}
