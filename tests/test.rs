use simple_logger::SimpleLogger;
use wtun::*;

#[test]
fn creates_adapter() {
  drop(SimpleLogger::new().init());
  let test_guid = None;
  let _adapter = Adapter::create("test", "test type", test_guid).unwrap();
}