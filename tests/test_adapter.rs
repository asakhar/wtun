use simple_logger::SimpleLogger;
use wtun::*;

#[test]
fn creates_adapter() {
  drop(SimpleLogger::new().init());
  let test_guid = None;
  let _adapter = Adapter::create("test", "test type", test_guid).unwrap();
}

#[test]
fn creates_adapter_and_opens() {
  drop(SimpleLogger::new().init());
  let test_guid = Some(winapi::shared::guiddef::GUID {
    Data1: 0xdeadbabe,
    Data2: 0xcafe,
    Data3: 0xbeef,
    Data4: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
  });
  let _adapter = Adapter::create("test", "test type", test_guid).unwrap();
  let _adapter1 = Adapter::open("test").unwrap();
}

#[test]
fn creates_adapter_and_sets_ipv4() {
  drop(SimpleLogger::new().init());
  let mut adapter = Adapter::create("test", "test type", None).unwrap();
  loop {
    match adapter.set_ip_address(ip_mask!(192.168.10 .1 / 24)) {
      Ok(_) => break,
      Err(err) => eprintln!("Error: {err}"),
    }
  }
}

#[test]
fn creates_adapter_and_sets_ipv6() {
  drop(SimpleLogger::new().init());
  let mut adapter = Adapter::create("test", "test type", None).unwrap();
  loop {
    match adapter.set_ip_address(ip_mask!(fe80: : : :b321:fb01:9ad8:e6e6/17)) {
      Ok(_) => break,
      Err(err) => eprintln!("Error: {err}"),
    }
  }
  let session = adapter
    .start_session(ring_capacity!(MAX_RING_CAPACITY))
    .unwrap();
  assert_eq!(session.is_write_avaliable().unwrap(), true);
}

#[test]
fn creates_adapter_and_sets_both_ip() {
  drop(SimpleLogger::new().init());
  let mut adapter = Adapter::create("test", "test type", None).unwrap();
  loop {
    match adapter.set_ip_address(ip_mask!(192.168.10 .1 / 24)) {
      Ok(_) => break,
      Err(err) => eprintln!("Error: {err}"),
    }
  }
  loop {
    match adapter.set_ip_address(ip_mask!(fe80: : : :b321:fb01:9ad8:e6e6/17)) {
      Ok(_) => break,
      Err(err) => eprintln!("Error: {err}"),
    }
  }
}
