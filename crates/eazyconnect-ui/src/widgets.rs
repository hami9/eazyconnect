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
        .fill(pal.accent)
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

pub fn nav_btn(ui: &mut Ui, pal: &ThemePalette, label: &str, selected: bool) -> Response {
    ui.add(
        egui::Button::new(RichText::new(label).strong().color(pal.text_primary))
            .selected(selected)
            .frame_when_inactive(selected)
            .min_size(Vec2::new(0.0, 34.0)),
    )
}

pub fn field(ui: &mut Ui, label: &str, value: &mut String, hint: &str, password: bool) -> Response {
    let label = ui.label(RichText::new(label).strong());
    ui.add(
        egui::TextEdit::singleline(value)
            .desired_width(f32::INFINITY)
            .margin(Margin::symmetric(10, 8))
            .hint_text(hint)
            .password(password),
    )
    .labelled_by(label.id)
}

pub fn attach_circle_btn(ui: &mut Ui, pal: &ThemePalette, tooltip: &str) -> Response {
    let size = 32.0;
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::click());
    let hovered = resp.hovered();
    let fill = if hovered { pal.accent } else { pal.hover_bg };
    let fg = if hovered {
        Color32::WHITE
    } else {
        pal.text_primary
    };
    ui.painter().circle_filled(rect.center(), size * 0.5, fill);
    if hovered {
        ui.painter()
            .circle_stroke(rect.center(), size * 0.5, Stroke::new(1.2, pal.accent_neon));
    }
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
                    egui::Image::new((tex.id(), sz * scale)).corner_radius(CornerRadius::same(8)),
                );
                ui.add_space(8.0);
            }
            ui.horizontal(|ui| {
                Frame::new()
                    .fill(pal.accent)
                    .stroke(Stroke::new(
                        1.0,
                        Color32::from_rgba_unmultiplied(
                            pal.accent_neon.r(),
                            pal.accent_neon.g(),
                            pal.accent_neon.b(),
                            150,
                        ),
                    ))
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
