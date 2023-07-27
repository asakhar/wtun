use winapi::shared::minwindef::DWORD;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub(crate) struct VS_FIXEDFILEINFO {
  pub(crate) dwSignature: DWORD,
  pub(crate) dwStrucVersion: DWORD,
  pub(crate) dwFileVersionMS: DWORD,
  pub(crate) dwFileVersionLS: DWORD,
  pub(crate) dwProductVersionMS: DWORD,
  pub(crate) dwProductVersionLS: DWORD,
  pub(crate) dwFileFlagsMask: DWORD,
  pub(crate) dwFileFlags: DWORD,
  pub(crate) dwFileOS: DWORD,
  pub(crate) dwFileType: DWORD,
  pub(crate) dwFileSubtype: DWORD,
  pub(crate) dwFileDateMS: DWORD,
  pub(crate) dwFileDateLS: DWORD,
}
