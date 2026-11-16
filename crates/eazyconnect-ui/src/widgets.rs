use egui::{
    Align, Color32, CornerRadius, Frame, Layout, Margin, Response, RichText, Sense, Stroke,
    TextureHandle, Ui, Vec2,
};

use crate::theme::ThemePalette;

pub fn primary_btn(
    ui: &mut Ui,
    pal: &ThemePalette,
    label: &str,
    min_width: f32,
    height: f32,
) -> Response {
    ui.add(
        egui::Button::new(
            RichText::new(label)
                .size(13.5)
                .strong()
                .color(Color32::WHITE),
        )
        .fill(pal.blurple)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(8))
        .min_size(Vec2::new(min_width, height)),
    )
}

pub fn secondary_btn(ui: &mut Ui, pal: &ThemePalette, label: &str, height: f32) -> Response {
    ui.add(
        egui::Button::new(
            RichText::new(label)
                .size(13.0)
                .strong()
                .color(pal.text_primary),
        )
        .fill(pal.composer_bg)
        .stroke(Stroke::new(1.0, pal.border))
        .corner_radius(CornerRadius::same(8))
        .min_size(Vec2::new(0.0, height)),
    )
}

pub fn danger_btn(ui: &mut Ui, pal: &ThemePalette, label: &str) -> Response {
    ui.add(
        egui::Button::new(RichText::new(label).size(13.0).strong().color(pal.danger))
            .fill(Color32::from_rgba_unmultiplied(
                pal.danger.r(),
                pal.danger.g(),
                pal.danger.b(),
                22,
            ))
            .stroke(Stroke::new(1.0, pal.danger))
            .corner_radius(CornerRadius::same(8))
            .min_size(Vec2::new(0.0, 32.0)),
    )
}

pub fn rail_squircle_btn(
    ui: &mut Ui,
    pal: &ThemePalette,
    text: &str,
    tooltip: &str,
    active: bool,
    size: f32,
) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::click());
    let hovered = resp.hovered();
    let radius = if active || hovered { 14 } else { (size * 0.5) as u8 };
    let fill = if active {
        pal.blurple
    } else if hovered {
        Color32::from_rgb(104, 117, 245)
    } else {
        pal.dock_bg
    };
    let fg = if active || hovered {
        Color32::WHITE
    } else {
        pal.text_primary
    };
    ui.painter()
        .rect_filled(rect, CornerRadius::same(radius), fill);
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        text,
        egui::FontId::proportional((size * 0.34).max(12.0)),
        fg,
    );
    resp.on_hover_text(tooltip)
}

pub fn attach_circle_btn(ui: &mut Ui, pal: &ThemePalette, tooltip: &str) -> Response {
    let size = 32.0;
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::click());
    let hovered = resp.hovered();
    let fill = if hovered { pal.blurple } else { pal.hover_bg };
    let fg = if hovered {
        Color32::WHITE
    } else {
        pal.text_primary
    };
    ui.painter().circle_filled(rect.center(), size * 0.5, fill);
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        "+",
        egui::FontId::proportional(19.0),
        fg,
    );
    resp.on_hover_text(tooltip)
}

pub fn unread_badge(ui: &mut Ui, pal: &ThemePalette, count: u32) {
    let label = if count > 99 {
        "99+".to_string()
    } else {
        count.to_string()
    };
    Frame::new()
        .fill(pal.danger)
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(7, 2))
        .show(ui, |ui| {
            ui.label(
                RichText::new(label)
                    .size(11.0)
                    .strong()
                    .color(Color32::WHITE),
            );
        });
}

#[allow(clippy::too_many_arguments)]
pub fn file_attachment_card(
    ui: &mut Ui,
    pal: &ThemePalette,
    filename: &str,
    size_label: &str,
    preview: Option<&TextureHandle>,
    max_width: f32,
) -> bool {
    let mut save_clicked = false;
    Frame::new()
        .fill(pal.sidebar_bg)
        .stroke(Stroke::new(1.0, pal.border))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::same(12))
        .show(ui, |ui| {
            ui.set_max_width(max_width.clamp(210.0, 380.0));
            if let Some(tex) = preview {
                let sz = tex.size_vec2();
                let scale = (260.0 / sz.x.max(1.0)).min(160.0 / sz.y.max(1.0)).min(1.0);
                ui.add(
                    egui::Image::new((tex.id(), sz * scale))
                        .corner_radius(CornerRadius::same(8)),
                );
                ui.add_space(8.0);
            }
            ui.horizontal(|ui| {
                Frame::new()
                    .fill(pal.blurple)
                    .corner_radius(CornerRadius::same(8))
                    .inner_margin(Margin::symmetric(9, 7))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new("FILE")
                                .size(11.0)
                                .strong()
                                .color(Color32::WHITE),
                        );
                    });
                ui.add_space(4.0);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 1.0;
                    ui.label(
                        RichText::new(filename)
                            .size(13.5)
                            .strong()
                            .color(pal.text_primary),
                    );
                    ui.label(
                        RichText::new(format!("{size_label}  •  End-to-End Encrypted"))
                            .size(11.5)
                            .color(pal.text_muted),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if secondary_btn(ui, pal, "Save", 28.0).clicked() {
                        save_clicked = true;
                    }
                });
            });
        });
    save_clicked
}
