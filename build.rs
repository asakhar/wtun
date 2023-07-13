use std::{process::{Command, Stdio}, io::Write};

fn main() {
  // let nci = ";$(IntDir)nci.lib";
  let additional_deps = "Cfgmgr32.lib;Iphlpapi.lib;onecore.lib;ntdll.lib;Setupapi.lib;shlwapi.lib;swdevice.lib;version.lib".split(';');
  for dep in additional_deps {
    println!(
      "cargo:rustc-link-lib={}",
      dep.split(".lib").into_iter().next().unwrap()
    );
  }
  let output = std::fs::File::create("src/wintun_inf.rs").unwrap();
  let mut child = Command::new("cscript.exe")
    .args(&["/nologo", "src/driver-files/extract-driverver.js"])
    .stdin(Stdio::piped())
    .stdout(output).spawn().unwrap();
  child.stdin.take().unwrap().write_all(include_bytes!("src/driver-files/wintun.inf")).unwrap();
  child.wait().unwrap();
}
