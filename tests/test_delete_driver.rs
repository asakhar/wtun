use simple_logger::SimpleLogger;
use wtun::delete_driver;

#[test]
fn delete() {
  drop(SimpleLogger::new().init());
  delete_driver().unwrap();
}