use cutils::{defer, files::get_windows_dir_path, strings::{WideCString, WideCStr}};
use get_last_error::Win32Error;
use winapi::{
  shared::winerror::{ERROR_ACCESS_DENIED, ERROR_NOT_SUPPORTED},
  um::setupapi::{HDEVINFO, SP_DEVINFO_DATA},
};

use crate::{
  logger::error,
  resource::{self, create_temp_dir, ResId},
  wmain::get_system_params,
};

pub(crate) fn remove_instance(
  dev_info: HDEVINFO,
  dev_info_data: &mut SP_DEVINFO_DATA,
) -> std::io::Result<()> {
  todo!()
}
pub(crate) fn enable_instance(
  dev_info: HDEVINFO,
  dev_info_data: &mut SP_DEVINFO_DATA,
) -> std::io::Result<()> {
  todo!()
}
pub(crate) fn disable_instance(
  dev_info: HDEVINFO,
  dev_info_data: &mut SP_DEVINFO_DATA,
) -> std::io::Result<()> {
  todo!()
}
pub(crate) fn create_instance(instance_id: &mut WideCStr) -> std::io::Result<> {
  todo!()
}
fn execute_rundll32<'a>(
  function: &str,
  arguments: impl Iterator<Item = &'a str>,
) -> std::io::Result<WideCString> {
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
  let proc = match std::process::Command::new(rundll32_path)
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
      let err = Win32Error::new(
        err
          .raw_os_error()
          .map(|e| e as u32)
          .unwrap_or(ERROR_ACCESS_DENIED),
      );
      return Err(error!(err, "Failed to create process"));
    }
  };
  let output = match proc.wait_with_output() {
    Ok(res) => res,
    Err(err) => {
      let err = Win32Error::new(
        err
          .raw_os_error()
          .map(|e| e as u32)
          .unwrap_or(ERROR_ACCESS_DENIED),
      );
      return Err(error!(err, "Failed to create process"));
    }
  };
  

  cleanupDelete.run();
  cleanupDirectory.run();
  todo!()
}
