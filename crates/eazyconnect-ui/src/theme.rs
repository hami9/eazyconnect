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
            Self::DiscordDark => "Dark",
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
    pub accent: Color32,
    pub accent_neon: Color32,
    pub online: Color32,
    pub idle: Color32,
    pub danger: Color32,
}

pub fn palette(mode: ThemeMode) -> ThemePalette {
    match mode {
        ThemeMode::DiscordDark => ThemePalette {
            is_dark: true,
            rail_bg: Color32::from_rgb(18, 29, 33),
            sidebar_bg: Color32::from_rgb(23, 35, 39),
            dock_bg: Color32::from_rgb(20, 31, 35),
            chat_bg: Color32::from_rgb(15, 24, 28),
            composer_bg: Color32::from_rgb(32, 47, 52),
            hover_bg: Color32::from_rgb(37, 54, 59),
            selected_bg: Color32::from_rgb(39, 66, 68),
            card_bg: Color32::from_rgb(23, 35, 39),
            input_bg: Color32::from_rgb(15, 24, 28),
            border: Color32::from_rgb(52, 73, 78),
            text_primary: Color32::from_rgb(239, 247, 247),
            text_muted: Color32::from_rgb(163, 186, 190),
            accent: Color32::from_rgb(5, 110, 112),
            accent_neon: Color32::from_rgb(102, 222, 208),
            online: Color32::from_rgb(104, 215, 157),
            idle: Color32::from_rgb(245, 193, 104),
            danger: Color32::from_rgb(255, 144, 145),
        },
        ThemeMode::Midnight => ThemePalette {
            is_dark: true,
            rail_bg: Color32::from_rgb(8, 12, 19),
            sidebar_bg: Color32::from_rgb(13, 19, 28),
            dock_bg: Color32::from_rgb(10, 15, 23),
            chat_bg: Color32::from_rgb(16, 23, 34),
            composer_bg: Color32::from_rgb(24, 34, 48),
            hover_bg: Color32::from_rgb(22, 31, 44),
            selected_bg: Color32::from_rgb(30, 44, 60),
            card_bg: Color32::from_rgb(14, 21, 32),
            input_bg: Color32::from_rgb(9, 14, 21),
            border: Color32::from_rgb(34, 52, 68),
            text_primary: Color32::from_rgb(241, 245, 249),
            text_muted: Color32::from_rgb(148, 163, 184),
            accent: Color32::from_rgb(5, 110, 112),
            accent_neon: Color32::from_rgb(45, 245, 140),
            online: Color32::from_rgb(35, 209, 122),
            idle: Color32::from_rgb(240, 178, 50),
            danger: Color32::from_rgb(255, 144, 155),
        },
        ThemeMode::Light => ThemePalette {
            is_dark: false,
            rail_bg: Color32::from_rgb(227, 233, 234),
            sidebar_bg: Color32::from_rgb(242, 246, 246),
            dock_bg: Color32::from_rgb(233, 239, 240),
            chat_bg: Color32::from_rgb(255, 255, 255),
            composer_bg: Color32::from_rgb(236, 241, 242),
            hover_bg: Color32::from_rgb(225, 236, 237),
            selected_bg: Color32::from_rgb(209, 228, 229),
            card_bg: Color32::from_rgb(242, 246, 246),
            input_bg: Color32::from_rgb(255, 255, 255),
            border: Color32::from_rgb(208, 220, 222),
            text_primary: Color32::from_rgb(6, 12, 14),
            text_muted: Color32::from_rgb(74, 90, 94),
            accent: Color32::from_rgb(5, 102, 106),
            accent_neon: Color32::from_rgb(5, 102, 106),
            online: Color32::from_rgb(17, 111, 66),
            idle: Color32::from_rgb(134, 83, 15),
            danger: Color32::from_rgb(176, 35, 44),
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
    visuals.selection.bg_fill = p.accent;
    visuals.selection.stroke = Stroke::new(1.0, p.accent_neon);
    visuals.widgets.noninteractive.bg_fill = p.card_bg;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, p.text_primary);
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    visuals.widgets.inactive.bg_fill = p.composer_bg;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, p.border);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, p.text_primary);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(8);
    visuals.widgets.hovered.bg_fill = p.hover_bg;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, p.text_muted);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, p.text_primary);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(8);
    visuals.widgets.active.bg_fill = p.selected_bg;
    visuals.widgets.active.bg_stroke = Stroke::new(2.0, p.accent_neon);
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
    style.text_styles.insert(
        TextStyle::Button,
        FontId::proportional((font_size - 0.5).max(12.0)),
    );
    style.text_styles.insert(
        TextStyle::Small,
        FontId::proportional((font_size - 2.0).max(12.0)),
    );
    style
        .text_styles
        .insert(TextStyle::Heading, FontId::proportional(font_size + 5.0));
    ctx.set_global_style(style);
}
