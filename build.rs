fn main() {
  // let nci = ";$(IntDir)nci.lib";
  let additional_deps = "Cfgmgr32.lib;Iphlpapi.lib;onecore.lib;ntdll.lib;Setupapi.lib;shlwapi.lib;swdevice.lib;version.lib".split(';');
  for dep in additional_deps {
    println!("cargo:rustc-link-lib={}", dep.split(".lib").into_iter().next().unwrap());
  }
}