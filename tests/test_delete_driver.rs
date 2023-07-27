use wtun::delete_driver;

#[test]
fn delete() {
  delete_driver().unwrap();
}