#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod state;
mod theme;
mod widgets;

use std::path::PathBuf;
use std::sync::Arc;

use tokio::runtime::Builder;

use crate::app::EazyUiApp;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!(
            "EazyConnect Desktop Chat UI v{}\n\
             Usage: eazyconnect-ui [--config <path>] [--keystore-dir <dir>]",
            env!("CARGO_PKG_VERSION")
        );
        return;
    }

    let mut config_path: Option<PathBuf> = None;
    let mut keystore_dir: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    config_path = Some(PathBuf::from(v));
                }
            }
            "--keystore-dir" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    keystore_dir = Some(PathBuf::from(v));
                }
            }
            _ => {}
        }
        i += 1;
    }

    let rt = Arc::new(
        Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to start tokio runtime"),
    );

    let icon = build_app_icon();
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 740.0])
            .with_min_inner_size([440.0, 480.0])
            .with_icon(Arc::new(icon)),
        ..Default::default()
    };

    if let Err(err) = eframe::run_native(
        "EazyConnect",
        native_options,
        Box::new(move |cc| {
            Ok(Box::new(EazyUiApp::new(
                rt,
                config_path,
                keystore_dir,
                &cc.egui_ctx,
            )))
        }),
    ) {
        eprintln!("eazyconnect-ui failed to start: {err}");
        std::process::exit(1);
    }
}

fn build_app_icon() -> egui::IconData {
    let size = 32usize;
    let mut rgba = Vec::with_capacity(size * size * 4);
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - 15.5;
            let dy = y as f32 - 15.5;
            let dist = (dx * dx + dy * dy).sqrt();
            let (r, g, b, a) = if dist < 13.5 {
                let inner = (9..23).contains(&x) && (9..23).contains(&y);
                if inner {
                    (242, 243, 245, 255)
                } else {
                    (88, 101, 242, 255) // Discord Blurple emblem
                }
            } else {
                (0, 0, 0, 0)
            };
            rgba.extend_from_slice(&[r, g, b, a]);
        }
    }
    egui::IconData {
        rgba,
        width: size as u32,
        height: size as u32,
    }
}
