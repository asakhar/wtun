use std::io::BufRead;

use cutils::{defer, files::get_windows_dir_path, inspection::GetPtrExt, strings::StaticWideCStr};
use get_last_error::Win32Error;
use winapi::{
  shared::{
    minwindef::FALSE,
    winerror::{
      ERROR_ACCESS_DENIED, ERROR_INVALID_DATA, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED,
      ERROR_SUCCESS,
    },
  },
  um::{
    cfgmgr32::MAX_DEVICE_ID_LEN,
    setupapi::{SetupDiGetDeviceInstanceIdW, HDEVINFO, SP_DEVINFO_DATA},
    winnt::{IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64},
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
pub(crate) fn create_instance() -> std::io::Result<StaticWideCStr<MAX_DEVICE_ID_LEN>> {
  info!("Spawning native process to create instance");
  let response = execute_rundll32("CreateInstanceWin7", &[])
    .map_err(|err| error!(err, "Error executing worker process"))?;
  let resp_text = String::from_utf16(&response).map_err(|err| {
    error!(
      ERROR_INVALID_DATA,
      "Failed to read process output ({err:?}): {:?}", response
    )
  })?;
  let (error, inst_id) = resp_text
    .split_once(' ')
    .and_then(|(error_hex, inst_id)| {
      u32::from_str_radix(&error_hex, 16)
        .ok()
        .map(|err| (err, inst_id))
    })
    .ok_or(error!(
      ERROR_INVALID_PARAMETER,
      "Incomplete response: {}", resp_text
    ))?;
  if error != ERROR_SUCCESS {
    return Err(error!(error, "Failed to create instance via rundll32"));
  }
  StaticWideCStr::<MAX_DEVICE_ID_LEN>::encode(inst_id).ok_or(error!(
    ERROR_INVALID_PARAMETER,
    "Invalid response: {:?}", response
  ))
}
fn execute_rundll32(function: &str, arguments: &[&str]) -> std::io::Result<Vec<u16>> {
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
    drop(std::fs::remove_dir_all(&random_temp_subdir));
  };
  let dll_path = random_temp_subdir.join("setupapihost.dll");
  let native_machine = unsafe { get_system_params().NativeMachine };
  let resource_id = match native_machine {
    IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_ARM64 => ResId::SetupApiHost,
    _ => {
      return Err(error!(
        Win32Error::new(ERROR_NOT_SUPPORTED),
        "Unsupported platform 0x{:x}", native_machine
      ))
    }
  };
  defer! { cleanupDelete <-
    drop(std::fs::remove_file(&dll_path));
  };
  if let Err(err) = resource::copy_to_file(&dll_path, resource_id) {
    return Err(error!(
      err,
      "Failed to copy resource {:?} to {}",
      resource_id,
      dll_path.display()
    ));
  }
  let arg = format!("{},{}", dll_path.display(), function);
  let args = std::iter::once(arg.as_str()).chain(arguments.iter().copied());
  let mut proc = match std::process::Command::new(rundll32_path)
    .args(args)
    .stderr(std::process::Stdio::piped())
    .stdout(std::process::Stdio::piped())
    .spawn()
  {
    Ok(res) => res,
    Err(err) => {
      return Err(error!(err, "Failed to create process"));
    }
  };
  let stderr = proc.stderr.take().unwrap();
  let mut stderr = std::io::BufReader::new(stderr);
  let mut read_log = |more: &mut bool| -> std::io::Result<()> {
    loop {
      let mut buf = String::new();
      let len = stderr.read_line(&mut buf)?;
      if len == 0 {
        *more = false;
        return Ok(());
      }
      let level = match buf.chars().next().unwrap() {
        '+' => crate::logger::Level::Info,
        '-' => crate::logger::Level::Warn,
        '!' => crate::logger::Level::Error,
        char => {
          return Err(error!(
            std::io::Error::new(
              std::io::ErrorKind::InvalidData,
              format!("Invalid level glyph: '{char}'")
            ),
            "Native process provided invalid log entry: {}", buf
          ))
        }
      };
      log::log!(target: "rundll32", level, "{}", &buf[1..]);
    }
  };
  let mut more = true;
  while more || proc.try_wait().transpose().is_none() {
    if let Err(err) = read_log(&mut more) {
      error!(err, "Failed to fetch error log from native process");
    }
  }
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
  let aligned: Vec<_> = output
    .stdout
    .chunks_exact(2)
    .map(|w| u16::from_ne_bytes(unsafe { w.try_into().unwrap_unchecked() }))
    .filter(|x| *x != 0)
    .collect();
  Ok(aligned)
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
  let response = execute_rundll32(function, &[instance_id.as_str()])
    .map_err(|err| error!(err, "Error executing worker process: {}", instance_id))?;
  let resp_text = String::from_utf16(&response).map_err(|err| {
    error!(
      ERROR_INVALID_DATA,
      "Failed to read process output ({err:?}): {:?}", response
    )
  })?;
  let error = u32::from_str_radix(&resp_text, 16).map_err(|err| {
    error!(
      ERROR_INVALID_PARAMETER,
      "Incomplete response ({err:?}): {}", resp_text
    )
  })?;
  if error != ERROR_SUCCESS {
    Err(std::io::Error::from_raw_os_error(error as i32))
  } else {
    Ok(())
  }
}
