fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        println!("cargo:rustc-cfg=wgnt_handwritten_bindings");
        return;
    }

    let header = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../wireguard-nt/api/wireguard.h");

    if !header.exists() {
        println!(
            "cargo:warning=wireguard.h not found at {}, using hand-written bindings",
            header.display()
        );
        println!("cargo:rustc-cfg=wgnt_handwritten_bindings");
        return;
    }

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let bindings_path = out_dir.join("wireguard_bindings.rs");

    match try_bindgen(&header, &bindings_path) {
        Ok(()) => {
            println!("cargo:rustc-cfg=wgnt_bindgen");
            println!("cargo:rerun-if-changed={}", header.display());
        }
        Err(e) => {
            println!("cargo:warning=bindgen failed ({e}), using hand-written bindings");
            println!("cargo:rustc-cfg=wgnt_handwritten_bindings");
        }
    }
}

fn try_bindgen(header: &std::path::Path, out: &std::path::Path) -> Result<(), String> {
    let bindings = bindgen::Builder::default()
        .header(header.to_string_lossy())
        .allowlist_type("WIREGUARD_.*")
        .allowlist_var("WIREGUARD_.*")
        .allowlist_function("WireGuard.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .map_err(|e| e.to_string())?;

    bindings.write_to_file(out).map_err(|e| e.to_string())
}
