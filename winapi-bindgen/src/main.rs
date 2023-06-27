extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
  let file = "swdevicedef";
    // Find the Windows SDK include directory
    let sdk_dir = match env::var("WINDOWSSDKDIR") {
        Ok(val) => PathBuf::from(val),
        Err(_) => PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10\"), // Update the path based on your SDK version
    }.join(r"Include\10.0.22621.0\");
    let shared = sdk_dir.join("shared");

    // Generate bindings using bindgen
    let bindings = bindgen::Builder::default()
        .header(format!(r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um\{}.h", file)) // Replace with the path to your header file
        .clang_arg(format!("-I{}", sdk_dir.to_str().unwrap()))
        .clang_arg(format!("-I{}", shared.to_str().unwrap()))
        .clang_arg("--target=x86_64-pc-windows-msvc") // Specify the target architecture
        .clang_arg("-D_AMD64_") // Specify the target architecture
        .clang_arg("-D_WIN32_WINNT=0x0500")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Failed to generate bindings");

    // Write the bindings to a file
    let out_path = PathBuf::from("");
    bindings
        .write_to_file(out_path.join(format!("{file}.rs")))
        .expect("Failed to write bindings");
}
