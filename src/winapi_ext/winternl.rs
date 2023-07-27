use winapi::shared::{ntdef::{NTSTATUS, PVOID}, minwindef::{ULONG, PULONG}};
extern "system" {
  pub(crate) fn RtlNtStatusToDosError(Status: NTSTATUS) -> ULONG;
  pub(crate) fn NtQuerySystemInformation(
    SystemInformationClass: SYSTEM_INFORMATION_CLASS,
    SystemInformation: PVOID,
    SystemInformationLength: ULONG,
    ReturnLength: PULONG,
  ) -> NTSTATUS;
}

pub type SYSTEM_INFORMATION_CLASS = ::std::os::raw::c_int;