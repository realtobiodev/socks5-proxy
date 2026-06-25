use std::fmt::Write as _;
use std::path::Path;

fn main() {
    // Embed a Windows application manifest that requests `requireAdministrator`.
    // The app performs host-wide TUN routing + WFP mutation, both of which need
    // an elevated session; without this the GUI starts non-elevated and every
    // TUN start fails. Supplying a custom manifest replaces Tauri's default, so
    // the file mirrors the settings Tauri would otherwise inject (Common-Controls
    // dependency, DPI awareness, longPathAware, supportedOS).
    #[cfg(windows)]
    {
        let windows = tauri_build::WindowsAttributes::new()
            .app_manifest(include_str!("windows-app.manifest"));
        tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
            .expect("failed to run tauri-build");
    }

    #[cfg(not(windows))]
    tauri_build::build();

    generate_flag_table();
}

/// Embed the pre-rasterized 32x32 RGBA country flags (flags_rgba/<cc>.rgba) into
/// the binary as a `cc -> &'static [u8]` lookup. Windows fonts can't render flag
/// emoji, so the tray composites these raster flags with a status dot instead.
fn generate_flag_table() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let flags_dir = Path::new(&manifest_dir).join("flags_rgba");
    println!("cargo:rerun-if-changed=flags_rgba");

    // Flags are only used by the Windows tray (Windows can't render flag emoji).
    // On other targets emit an empty table so the binary stays lean and the module
    // still compiles if referenced.
    let windows_target =
        std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");

    let mut arms = String::new();
    if windows_target {
    if let Ok(entries) = std::fs::read_dir(&flags_dir) {
        let mut files: Vec<_> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|x| x == "rgba").unwrap_or(false))
            .collect();
        files.sort();
        for path in files {
            let cc = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if cc.len() != 2 || !cc.chars().all(|c| c.is_ascii_lowercase()) {
                continue;
            }
            let abs = path.to_string_lossy().replace('\\', "\\\\");
            let _ = writeln!(
                arms,
                "        \"{cc}\" => Some(&include_bytes!(\"{abs}\")[..]),"
            );
        }
    }
    }

    let code = format!(
        "/// Side length of each embedded flag bitmap (square RGBA8).\n\
         pub const FLAG_RGBA_SIZE: u32 = 32;\n\
         /// Raw RGBA8 bytes for a country flag by lowercase ISO-3166 alpha-2 code.\n\
         pub fn flag_rgba(cc: &str) -> Option<&'static [u8]> {{\n\
         \x20   match cc {{\n{arms}        _ => None,\n    }}\n}}\n"
    );

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::write(Path::new(&out_dir).join("flags_generated.rs"), code)
        .expect("failed to write flags_generated.rs");
}
