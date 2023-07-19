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
  #[cfg(any(target_arch = "x86", target_arch = "arm", target_arch = "x86_64"))] {
    #[cfg(feature = "windows7")]
    macro_rules! toggle_windows7 {
      ($command:ident) => {
        let $command = $command.arg("features=windows7");
      };
    }
    #[cfg(not(feature = "windows7"))]
    macro_rules! toggle_windows7 {
      ($command:ident) => {};
    }
    #[cfg(not(debug_assertions))]
    macro_rules! toggle_release {
      ($command:ident) => {
        let $command = $command.arg("--release");
      };
    }
    #[cfg(debug_assertions)]
    macro_rules! toggle_release {
      ($command:ident) => {};
    }
    let mut command = Command::new(env!("CARGO"));
    let command = command.current_dir("setupapihost").arg("build");
    toggle_windows7!(command);
    toggle_release!(command);
    command.spawn().unwrap().wait().unwrap();
    // TODO!: copy resulting library into expected resource place
  }
}
