use egui::{Color32, CornerRadius, FontId, Margin, Stroke, TextStyle, Visuals};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeMode {
    DiscordDark,
    Midnight,
    Light,
}

impl ThemeMode {
    pub fn from_config(val: Option<&str>) -> Self {
        match val.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("midnight") => Self::Midnight,
            Some("light") => Self::Light,
            _ => Self::DiscordDark,
        }
    }

    pub fn as_key(self) -> &'static str {
        match self {
            Self::DiscordDark => "discord_dark",
            Self::Midnight => "midnight",
            Self::Light => "light",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::DiscordDark => "Discord Dark",
            Self::Midnight => "Midnight OLED",
            Self::Light => "Clean Light",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ThemePalette {
    pub is_dark: bool,
    pub rail_bg: Color32,
    pub sidebar_bg: Color32,
    pub dock_bg: Color32,
    pub chat_bg: Color32,
    pub composer_bg: Color32,
    pub hover_bg: Color32,
    pub selected_bg: Color32,
    pub card_bg: Color32,
    pub input_bg: Color32,
    pub border: Color32,
    pub text_primary: Color32,
    pub text_muted: Color32,
    pub blurple: Color32,
    pub online: Color32,
    pub idle: Color32,
    pub danger: Color32,
}

pub fn palette(mode: ThemeMode) -> ThemePalette {
    match mode {
        ThemeMode::DiscordDark => ThemePalette {
            is_dark: true,
            rail_bg: Color32::from_rgb(30, 31, 34),      // #1E1F22
            sidebar_bg: Color32::from_rgb(43, 45, 49),   // #2B2D31
            dock_bg: Color32::from_rgb(35, 36, 40),      // #232428
            chat_bg: Color32::from_rgb(49, 51, 56),      // #313338
            composer_bg: Color32::from_rgb(56, 58, 64),  // #383A40
            hover_bg: Color32::from_rgb(53, 55, 60),
            selected_bg: Color32::from_rgb(64, 66, 73),
            card_bg: Color32::from_rgb(43, 45, 49),
            input_bg: Color32::from_rgb(30, 31, 34),
            border: Color32::from_rgb(63, 65, 71),
            text_primary: Color32::from_rgb(242, 243, 245),
            text_muted: Color32::from_rgb(148, 155, 164),
            blurple: Color32::from_rgb(88, 101, 242),    // #5865F2
            online: Color32::from_rgb(35, 165, 90),      // #23A55A
            idle: Color32::from_rgb(240, 178, 50),       // #F0B232
            danger: Color32::from_rgb(242, 63, 67),      // #F23F43
        },
        ThemeMode::Midnight => ThemePalette {
            is_dark: true,
            rail_bg: Color32::from_rgb(9, 11, 16),
            sidebar_bg: Color32::from_rgb(15, 19, 28),
            dock_bg: Color32::from_rgb(12, 15, 22),
            chat_bg: Color32::from_rgb(19, 23, 34),
            composer_bg: Color32::from_rgb(28, 33, 48),
            hover_bg: Color32::from_rgb(26, 31, 46),
            selected_bg: Color32::from_rgb(35, 42, 62),
            card_bg: Color32::from_rgb(17, 22, 34),
            input_bg: Color32::from_rgb(11, 14, 21),
            border: Color32::from_rgb(39, 47, 68),
            text_primary: Color32::from_rgb(241, 245, 249),
            text_muted: Color32::from_rgb(148, 163, 184),
            blurple: Color32::from_rgb(88, 101, 242),
            online: Color32::from_rgb(35, 165, 90),
            idle: Color32::from_rgb(240, 178, 50),
            danger: Color32::from_rgb(244, 63, 94),
        },
        ThemeMode::Light => ThemePalette {
            is_dark: false,
            rail_bg: Color32::from_rgb(227, 229, 232),
            sidebar_bg: Color32::from_rgb(242, 243, 245),
            dock_bg: Color32::from_rgb(235, 237, 239),
            chat_bg: Color32::from_rgb(255, 255, 255),
            composer_bg: Color32::from_rgb(235, 237, 239),
            hover_bg: Color32::from_rgb(230, 232, 236),
            selected_bg: Color32::from_rgb(218, 220, 226),
            card_bg: Color32::from_rgb(242, 243, 245),
            input_bg: Color32::from_rgb(255, 255, 255),
            border: Color32::from_rgb(216, 218, 222),
            text_primary: Color32::from_rgb(6, 6, 7),
            text_muted: Color32::from_rgb(78, 80, 88),
            blurple: Color32::from_rgb(88, 101, 242),
            online: Color32::from_rgb(35, 165, 90),
            idle: Color32::from_rgb(217, 145, 22),
            danger: Color32::from_rgb(218, 55, 60),
        },
    }
}

pub fn apply_theme_to_ctx(ctx: &egui::Context, mode: ThemeMode, font_size: f32) {
    let p = palette(mode);
    let mut visuals = if p.is_dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    visuals.window_fill = p.chat_bg;
    visuals.panel_fill = p.sidebar_bg;
    visuals.extreme_bg_color = p.input_bg;
    visuals.faint_bg_color = p.card_bg;
    visuals.selection.bg_fill = p.blurple;
    visuals.selection.stroke = Stroke::new(1.0, p.blurple);
    visuals.widgets.noninteractive.bg_fill = p.card_bg;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, p.text_primary);
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    visuals.widgets.inactive.bg_fill = p.composer_bg;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, p.text_primary);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(8);
    visuals.widgets.hovered.bg_fill = p.hover_bg;
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, p.text_primary);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(8);
    visuals.widgets.active.bg_fill = p.selected_bg;
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, p.text_primary);
    visuals.widgets.active.corner_radius = CornerRadius::same(8);
    visuals.widgets.open.corner_radius = CornerRadius::same(8);
    ctx.set_visuals(visuals);

    let mut style = (*ctx.global_style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(12.0, 7.0);
    style.spacing.window_margin = Margin::same(12);
    style
        .text_styles
        .insert(TextStyle::Body, FontId::proportional(font_size));
    style
        .text_styles
        .insert(TextStyle::Button, FontId::proportional((font_size - 0.5).max(12.0)));
    style
        .text_styles
        .insert(TextStyle::Small, FontId::proportional((font_size - 2.5).max(10.5)));
    style
        .text_styles
        .insert(TextStyle::Heading, FontId::proportional(font_size + 5.0));
    ctx.set_global_style(style);
}
