package app

import (
	"errors"
	"fmt"
	"mnemosyne/internal/config"
	"mnemosyne/internal/crypto"
	"mnemosyne/internal/domain"
	"mnemosyne/internal/parser"
	"mnemosyne/internal/snapshot"
	"mnemosyne/internal/store"
	"mnemosyne/internal/ui"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type Mode int

const (
	ModeUnlock Mode = iota
	ModeWelcome
	ModeDive
	ModeSurface
	ModeChangePassword
	ModeArchiveMeta
)

type tickMsg time.Time
type autosaveMsg struct{}

type Model struct {
	mode             Mode
	prevMode         Mode
	config           config.Config
	store            *store.SQLiteStore
	snapshotManager  *snapshot.SnapshotManager
	archiveMeta      *domain.ArchiveMeta
	dataKey          []byte // Kept for async snapshots, will be zeroed on lock/exit
	editor           textarea.Model
	searchInput      textinput.Model
	passwordInput    textinput.Model
	confirmInput     textinput.Model
	currentPassInput textinput.Model
	unlockStage      int // 0 = enter, 1 = confirm (first run)
	changePassStage  int // 0 = current, 1 = new, 2 = confirm
	isFirstRun       bool
	session          *domain.WritingSession
	entry            *domain.Entry
	lastInput        time.Time
	lastSave         time.Time
	dirty            bool
	entries          []domain.Entry
	triggers         []domain.Trigger
	width            int
	height           int
	cursorIndex      int
	confirmingDelete bool
	searching        bool
	themeIndex       int
	styles           ui.Styles
	err              error
}

func NewModel(s *store.SQLiteStore, dataDir string) Model {
	ta := textarea.New()
	ta.Placeholder = "Write your heart out..."
	ta.Focus()
	ta.Prompt = "  "

	si := textinput.New()
	si.Placeholder = "Search..."
	si.CharLimit = 64
	si.Width = 30

	pi := textinput.New()
	pi.Placeholder = "Password"
	pi.EchoMode = textinput.EchoPassword
	pi.EchoCharacter = '•'
	pi.Focus()
	pi.Width = 34

	ci := textinput.New()
	ci.Placeholder = "Confirm Password"
	ci.EchoMode = textinput.EchoPassword
	ci.EchoCharacter = '•'
	ci.Width = 34

	cp := textinput.New()
	cp.Placeholder = "Current Password"
	cp.EchoMode = textinput.EchoPassword
	cp.EchoCharacter = '•'
	cp.Width = 34

	initialStyles := ui.GetStyles(ui.Themes[0])

	conf := config.LoadConfig(config.GetConfigPath(dataDir))
	sm, _ := snapshot.NewSnapshotManager(s, filepath.Join(dataDir, "snapshots"))
	sm.SetMaxSnapshots(conf.SnapshotRetention)

	m := Model{
		mode:             ModeWelcome,
		config:           conf,
		store:            s,
		snapshotManager:  sm,
		editor:           ta,
		searchInput:      si,
		passwordInput:    pi,
		confirmInput:     ci,
		currentPassInput: cp,
		styles:           initialStyles,
		lastInput:        time.Now(),
	}

	enabled, err := s.IsEncryptionEnabled()
	if err != nil {
		m.err = err
	} else if enabled {
		m.mode = ModeUnlock
		m.isFirstRun = false
	} else {
		entries, err := s.GetEntries()
		if err != nil {
			m.err = err
		} else if len(entries) == 0 {
			m.isFirstRun = true
			m.mode = ModeUnlock
			m.passwordInput.Placeholder = "Set a Master Password (optional, ESC to skip)"
		} else {
			m.entries = entries
		}
	}

	return m
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(textarea.Blink, tick(), m.autosave())
}

func tick() tea.Cmd {
	return tea.Every(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m Model) autosave() tea.Cmd {
	return tea.Every(time.Duration(m.config.AutosaveSeconds)*time.Second, func(t time.Time) tea.Msg { return autosaveMsg{} })
}

// performLock saves dirty state, zeros key material, and returns to ModeUnlock.
func (m Model) performLock() (tea.Model, tea.Cmd) {
	if m.mode == ModeDive || m.mode == ModeSurface {
		m.save()
	}

	if m.dataKey != nil {
		_ = m.snapshotManager.TriggerSnapshot(m.dataKey, false)
		crypto.Zero(m.dataKey)
		m.dataKey = nil
	}
	m.store.SetKey(nil)

	m.mode = ModeUnlock
	m.unlockStage = 0
	m.isFirstRun = false
	m.passwordInput.SetValue("")
	m.passwordInput.Placeholder = "Password"
	m.passwordInput.Focus()
	m.confirmInput.SetValue("")
	m.err = nil

	return m, nil
}

func (m *Model) createNewEntry() {
	m.entry = nil; m.editor.SetValue(""); m.session = nil; m.triggers = nil; m.dirty = false; m.lastSave = time.Time{}
}

func (m *Model) loadEntry(id int64) {
	e, err := m.store.GetEntry(id)
	if err == nil {
		m.entry = e
		m.editor.SetValue(e.Body)
		m.session = &domain.WritingSession{
			EntryID:   e.ID,
			StartedAt: time.Now(),
		}
		if err := m.store.CreateSession(m.session); err != nil {
			m.err = fmt.Errorf("failed to start writing session: %w", err)
			m.session = nil
		}
		m.dirty = false
		m.lastSave = time.Now()
	} else {
		m.err = err
	}
}

func (m *Model) updateLayout() {
	// Ensure we have reasonable minimums
	if m.width < 20 { m.width = 20 }
	if m.height < 10 { m.height = 10 }

	// Calculate editor width
	// Base overhead: Main padding (6) + Editor internal padding left (2) = 8
	ew := m.width - 8
	
	if m.mode == ModeSurface {
		// HUD width is ~36. Total overhead with HUD = 45.
		// If terminal is too narrow, we prioritize editor width or hide HUD.
		if m.width > 72 {
			ew = m.width - 45
		} else if m.width > 58 {
			// Shrink editor to its minimum
			ew = 20
		} else {
			// Very narrow: Editor takes full available width, HUD will be hidden in View()
			ew = m.width - 8
		}
	}
	
	if ew < 10 { ew = 10 }
	
	m.editor.SetWidth(ew)
	m.editor.SetHeight(m.height - 8)
}

func deriveTitle(body string) string {
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			title := strings.TrimLeft(trimmed, "# ")
			runes := []rune(title)
			if len(runes) > 60 {
				title = string(runes[:57]) + "..."
			}
			return title
		}
	}
	return "Untitled Entry"
}

func (m *Model) save() {
	body := m.editor.Value(); words := len(strings.Fields(body))
	if words == 0 { return }
	
	title := deriveTitle(body)

	if m.entry == nil {
		m.entry = &domain.Entry{Title: title, Body: body, WordCount: words}
		if err := m.store.CreateEntry(m.entry); err != nil {
			m.err = fmt.Errorf("initial save failed: %w", err)
			m.entry = nil 
			return
		}
	} else {
		m.entry.Title = title; m.entry.Body = body; m.entry.WordCount = words
	}
	
	if m.session == nil {
		m.session = &domain.WritingSession{EntryID: m.entry.ID, StartedAt: time.Now()}
		if err := m.store.CreateSession(m.session); err != nil {
			m.err = fmt.Errorf("session init failed: %w", err)
			m.session = nil
			return
		}
	}
	
	m.session.WordsAdded = words; now := time.Now(); m.session.EndedAt = &now
	trigs, err := parser.ScanContent(m.entry.ID, m.session.ID, body)
	if err != nil {
		m.err = fmt.Errorf("scan triggers: %w", err)
		return
	}

	if err := m.store.SaveAll(m.entry, m.session, trigs); err == nil {
		m.lastSave = now
		if m.dataKey != nil {
			m.snapshotManager.NotifyWrite(m.dataKey)
		}
	} else {
		m.err = err
		if errors.Is(err, store.ErrEntryDeleted) {
			m.createNewEntry()
			m.entries, m.err = m.store.GetEntries()
		}
	}
}

