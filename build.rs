use std::{
  io::Write,
  process::{Command, Stdio},
};

fn main() {
  let link_libs = [
    "Cfgmgr32",
    "OneCoreUAP",
    "Iphlpapi",
    "onecore",
    "ntdll",
    "Setupapi",
    "shlwapi",
    "swdevice",
    "version",
  ];
  for dep in link_libs {
    println!("cargo:rustc-link-lib={}", dep);
  }
  const DRIVER_SUFFIXES: [&str; 12] = [
    "x86.cat",
    "x86.sys",
    "x86.inf",
    "amd64.cat",
    "amd64.sys",
    "amd64.inf",
    "arm.cat",
    "arm.sys",
    "arm.inf",
    "arm64.cat",
    "arm64.sys",
    "arm64.inf",
  ];
  let mut any_inf = None;
  let output_dir = format!("{}/driver-files/", std::env::var("OUT_DIR").unwrap());
  std::fs::create_dir_all(&output_dir).unwrap();
  for suffix in DRIVER_SUFFIXES {
    let input = format!("src/driver-files/wintun-{suffix}");
    let output = format!("{}wintun-{suffix}", output_dir);
    if std::fs::copy(&input, &output).is_err() {
      std::fs::File::create(output).unwrap();
    } else {
      if suffix.ends_with(".inf") {
        any_inf = std::fs::read(input).ok();
      }
    }
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
    .write_all(&any_inf.expect("Not found any inf driver files in src/driver-files"))
    .unwrap();
  child.wait().unwrap();
  #[cfg(any(target_arch = "x86", target_arch = "arm", target_arch = "x86_64"))]
  {
    #[cfg(feature = "build_amd64_msvc_wow64")]
    build_wow64("x86_64-pc-windows-msvc");
    #[cfg(feature = "build_amd64_gnu_wow64")]
    build_wow64("x86_64-pc-windows-gnu");
    #[cfg(feature = "build_arm64_msvc_wow64")]
    build_wow64("aarch64-pc-windows-msvc");
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

fn build_wow64(target: &str) {
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
    ))
    .arg(format!("--target={target}"));
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
