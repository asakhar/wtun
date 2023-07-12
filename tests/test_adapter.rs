use chrono::offset::Utc;
use chrono::DateTime;
use std::time::SystemTime;
use wtun::*;

fn logger(level: LogLevel, timestamp: SystemTime, message: core::fmt::Arguments) {
  let timestamp: DateTime<Utc> = timestamp.into();
  eprintln!(
    "[{:?}] [{}] {}",
    level,
    timestamp.format("%d.%m.%Y %T"),
    message
  );
}

#[test]
fn creates_adapter() {
  set_logger(logger);
  // let test_guid = Some(winapi::shared::guiddef::GUID {
  //   Data1: 0xdeadbabe,
  //   Data2: 0xcafe,
  //   Data3: 0xbeef,
  //   Data4: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
  // });
  let test_guid = None;
  let _adapter = Adapter::create("test", "test type", test_guid).unwrap();
}

// #[test]
// fn creates_adapter_and_opens() {
//   set_logger(logger);
//   let test_guid = Some(winapi::shared::guiddef::GUID {
//     Data1: 0xdeadbabe,
//     Data2: 0xcafe,
//     Data3: 0xbeef,
//     Data4: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
//   });
//   let _adapter = Adapter::create("test", "test type", test_guid).unwrap();
//   std::mem::forget(_adapter);
//   let _adapter2 = Adapter::open("test").unwrap();
// }