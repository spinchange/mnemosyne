package ui

import "github.com/charmbracelet/lipgloss"

type Palette struct {
	Primary lipgloss.Color
	Accent  lipgloss.Color
	Muted   lipgloss.Color
	Subtle  lipgloss.Color // near-invisible: borders, rules
	Danger  lipgloss.Color // errors, delete confirm
	Bg      lipgloss.Color
	Card    lipgloss.Color // slightly lighter Bg for HUD panel
}

var Midnight = Palette{
	Primary: lipgloss.Color("#9d9bf4"), // softer lavender
	Accent:  lipgloss.Color("#e5c07b"), // warm amber
	Muted:   lipgloss.Color("#6e6e75"),
	Subtle:  lipgloss.Color("#3a3a3f"),
	Danger:  lipgloss.Color("#ff453a"),
	Bg:      lipgloss.Color("#1c1c1e"),
	Card:    lipgloss.Color("#2c2c2e"),
}

var Forest = Palette{
	Primary: lipgloss.Color("#4ac26b"),
	Accent:  lipgloss.Color("#e0956a"),
	Muted:   lipgloss.Color("#5a5a5f"),
	Subtle:  lipgloss.Color("#2a2e28"),
	Danger:  lipgloss.Color("#ff6b6b"),
	Bg:      lipgloss.Color("#1a1c19"),
	Card:    lipgloss.Color("#252820"),
}

var Sepia = Palette{
	Primary: lipgloss.Color("#c4996a"), // warmer
	Accent:  lipgloss.Color("#9a6e3a"),
	Muted:   lipgloss.Color("#8a7a65"),
	Subtle:  lipgloss.Color("#453d34"),
	Danger:  lipgloss.Color("#c0614a"),
	Bg:      lipgloss.Color("#1e1a16"),
	Card:    lipgloss.Color("#2a2420"),
}

var Themes = []Palette{Midnight, Forest, Sepia}

type Styles struct {
	Main          lipgloss.Style
	Editor        lipgloss.Style
	HUD           lipgloss.Style
	Title         lipgloss.Style
	Welcome       lipgloss.Style
	Label         lipgloss.Style
	Value         lipgloss.Style
	Trigger       lipgloss.Style
	SectionHead   lipgloss.Style
	StatusBar     lipgloss.Style
	Modal         lipgloss.Style
	ErrorMsg      lipgloss.Style
	EntrySelected lipgloss.Style
	EntryNormal   lipgloss.Style
	Divider       lipgloss.Style
}

func GetStyles(p Palette) Styles {
	return Styles{
		Main: lipgloss.NewStyle().
			Background(p.Bg).
			Padding(1, 3),

		// Dive: pure prose, no chrome
		Editor: lipgloss.NewStyle().
			PaddingLeft(2),

		// Surface: HUD panel has its own card feel
		HUD: lipgloss.NewStyle().
			Background(p.Card).
			Border(lipgloss.Border{Left: "▌"}, false, false, false, true).
			BorderForeground(p.Subtle).
			BorderBackground(p.Bg).
			PaddingLeft(3).
			PaddingRight(2).
			PaddingTop(1),

		// Primary title — used for MNEMOSYNE wordmark
		Title: lipgloss.NewStyle().
			Foreground(p.Primary).
			Bold(true),

		// Welcome tagline / date line
		Welcome: lipgloss.NewStyle().
			Foreground(p.Primary).
			Italic(true).
			MarginBottom(1),

		// Subdued label text
		Label: lipgloss.NewStyle().
			Foreground(p.Muted),

		// Bright value text
		Value: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#e8e8ed")).
			Bold(true),

		// Accent: triggers, cursor arrow, key hints
		Trigger: lipgloss.NewStyle().
			Foreground(p.Accent).
			Bold(true),

		// Section headers inside HUD (smaller, quieter than Title)
		SectionHead: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#a0a0a8")). // Slightly brighter than Muted
			Bold(true),

		// Dive-mode bottom status bar
		StatusBar: lipgloss.NewStyle().
			Foreground(p.Muted). // Lifted from Subtle for readability
			MarginTop(1).
			PaddingLeft(2),

		// Modal overlay box (Unlock, Change Password)
		Modal: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(p.Subtle).
			Background(p.Card).
			Padding(2, 4),

		// Error messages
		ErrorMsg: lipgloss.NewStyle().
			Foreground(p.Danger).
			MarginTop(1),

		// HUD entry list — selected row
		EntrySelected: lipgloss.NewStyle().
			Foreground(p.Accent).
			Bold(true),

		// HUD entry list — unselected row
		EntryNormal: lipgloss.NewStyle().
			Foreground(p.Muted),

		// Horizontal rule for HUD sections
		Divider: lipgloss.NewStyle().
			Foreground(p.Subtle),
	}
}
