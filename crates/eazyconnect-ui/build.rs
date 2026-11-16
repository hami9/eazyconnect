use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let ico_path = manifest_dir.join("..\\..\\installer\\eazyconnect.ico");
    println!("cargo:rerun-if-changed={}", ico_path.display());
    println!("cargo:rerun-if-changed=assets/logo.png");

    let Ok(ico_abs) = std::fs::canonicalize(&ico_path) else {
        println!(
            "cargo:warning=eazyconnect.ico not found at {}; skipping Windows PE icon resource",
            ico_path.display()
        );
        return;
    };

    let Some(rc_exe) = find_rc_exe() else {
        println!("cargo:warning=Windows SDK rc.exe not found; skipping Windows PE icon resource");
        return;
    };

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let rc_file = out_dir.join("eazyconnect.rc");
    let res_file = out_dir.join("eazyconnect.res");

    let rc_ico_str = ico_abs
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .replace('\\', "\\\\");
    let rc_contents = format!("1 ICON \"{rc_ico_str}\"\n");
    if let Err(e) = std::fs::write(&rc_file, rc_contents) {
        println!("cargo:warning=failed writing {}: {e}", rc_file.display());
        return;
    }

    let status = Command::new(&rc_exe)
        .arg("/nologo")
        .arg("/fo")
        .arg(&res_file)
        .arg(&rc_file)
        .status();

    match status {
        Ok(s) if s.success() && res_file.exists() => {
            println!("cargo:rustc-link-arg-bins={}", res_file.display());
        }
        Ok(s) => {
            println!("cargo:warning=rc.exe exited with status {s}; skipping Windows PE icon");
        }
        Err(e) => {
            println!("cargo:warning=failed executing rc.exe: {e}");
        }
    }
}

fn find_rc_exe() -> Option<PathBuf> {
    if let Ok(path_env) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_env) {
            let cand = dir.join("rc.exe");
            if cand.is_file() {
                return Some(cand);
            }
        }
    }

    let kits_bin = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    let mut versions: Vec<PathBuf> = std::fs::read_dir(kits_bin)
        .ok()?
        .filter_map(|e| e.ok().map(|v| v.path()))
        .filter(|p| p.is_dir())
        .collect();
    versions.sort();
    for ver in versions.into_iter().rev() {
        let cand = ver.join("x64").join("rc.exe");
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}
