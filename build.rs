use std::{
  io::Write,
  process::{Command, Stdio},
};

fn main() {
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
    .stdout(output)
    .spawn()
    .unwrap();
  child
    .stdin
    .take()
    .unwrap()
    .write_all(include_bytes!("src/driver-files/wintun.inf"))
    .unwrap();
  child.wait().unwrap();
  #[cfg(any(target_arch = "x86", target_arch = "arm", target_arch = "x86_64"))]
  {
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
    let command = command
    .stderr(Stdio::piped())
      .stdout(Stdio::piped())
      .current_dir("setupapihost")
      .arg("build")
      .arg(format!(
        "--target-dir={}/setupapihost",
        std::env::var("OUT_DIR").unwrap()
      ));
      toggle_windows7!(command);
      toggle_release!(command);

    let output = command.spawn().unwrap().wait_with_output().unwrap();
    if !output.status.success() {
      let code = output.status.code().unwrap_or(-1);
      eprintln!("Setupapihost compilation failed with exit code: {}", code);
      eprintln!("{}", String::from_utf8_lossy(&output.stderr));
      eprintln!("{}", String::from_utf8_lossy(&output.stdout));
      std::process::exit(code);
    }
  }
  #[cfg(feature = "request_elevation")]
  {
    let mut res = winres::WindowsResource::new();
    res
      .set_manifest(
        r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
        <requestedPrivileges>
            <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
        </requestedPrivileges>
    </security>
</trustInfo>
</assembly>
"#,
      )
      .compile()
      .unwrap();
  }
}
