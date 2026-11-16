#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod state;

use std::path::PathBuf;
use std::sync::Arc;

use egui::{Color32, CornerRadius, Visuals};
use tokio::runtime::Builder;

use crate::app::EazyUiApp;
use crate::state::{ACCENT_CYAN, BG_CANVAS, BG_INPUT, BG_PANEL, TEXT_PRIMARY};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!(
            "EazyConnect Native Desktop UI v{}\n\
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

    let icon = build_cube_icon();
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1080.0, 740.0])
            .with_min_inner_size([820.0, 560.0])
            .with_icon(Arc::new(icon)),
        ..Default::default()
    };

    if let Err(err) = eframe::run_native(
        "EazyConnect Control Center",
        native_options,
        Box::new(move |cc| {
            apply_dark_theme(&cc.egui_ctx);
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

fn apply_dark_theme(ctx: &egui::Context) {
    let mut visuals = Visuals::dark();
    visuals.window_fill = BG_CANVAS;
    visuals.panel_fill = BG_PANEL;
    visuals.extreme_bg_color = BG_INPUT;
    visuals.faint_bg_color = BG_PANEL;
    visuals.selection.bg_fill = Color32::from_rgb(14, 116, 144);
    visuals.selection.stroke.color = ACCENT_CYAN;
    visuals.widgets.noninteractive.fg_stroke.color = TEXT_PRIMARY;
    visuals.widgets.inactive.corner_radius = CornerRadius::same(6);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(6);
    visuals.widgets.active.corner_radius = CornerRadius::same(6);
    visuals.widgets.open.corner_radius = CornerRadius::same(6);
    ctx.set_visuals(visuals);
}

fn build_cube_icon() -> egui::IconData {
    let size = 32usize;
    let mut rgba = Vec::with_capacity(size * size * 4);
    for y in 0..size {
        for x in 0..size {
            let border = x < 2 || y < 2 || x >= size - 2 || y >= size - 2;
            let inner = (8..24).contains(&x) && (8..24).contains(&y);
            let ring = (5..27).contains(&x)
                && (5..27).contains(&y)
                && (x == 5 || x == 26 || y == 5 || y == 26);
            let (r, g, b, a) = if inner {
                (56, 189, 248, 255)
            } else if ring {
                (16, 185, 129, 255)
            } else if border {
                (30, 41, 59, 255)
            } else {
                (13, 18, 30, 255)
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
