package app

import (
	"errors"
	"fmt"
	"mnemosyne/internal/config"
	"mnemosyne/internal/crypto"
	"mnemosyne/internal/domain"
	"mnemosyne/internal/parser"
	"mnemosyne/internal/store"
	"mnemosyne/internal/snapshot"
	"mnemosyne/internal/ui"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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
	startTime        time.Time
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
		startTime:        time.Now(),
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

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.updateLayout()

	case tea.KeyMsg:
		m.lastInput = time.Now()
		keyStr := strings.ToLower(msg.String())

		if msg.String() == "ctrl+c" {
			if m.mode == ModeDive || m.mode == ModeSurface {
				m.save()
			}
			if m.dataKey != nil {
				_ = m.snapshotManager.TriggerSnapshot(m.dataKey, true)
				crypto.Zero(m.dataKey)
				m.dataKey = nil
			}
			m.store.SetKey(nil)
			return m, tea.Quit
		}

		if msg.String() == "ctrl+l" && m.dataKey != nil && m.mode != ModeUnlock {
			return m.performLock()
		}

		if m.mode == ModeArchiveMeta {
			if keyStr == "esc" || keyStr == "m" {
				m.mode = m.prevMode
			}
			return m, nil
		}

		if m.mode == ModeUnlock {
			switch msg.String() {
			case "esc":
				if m.isFirstRun {
					m.mode = ModeWelcome
					m.entries, m.err = m.store.GetEntries()
					return m, nil
				}
			case "enter":
				if m.isFirstRun {
					if m.unlockStage == 0 {
						if m.passwordInput.Value() == "" {
							m.mode = ModeWelcome
							m.entries, m.err = m.store.GetEntries()
							return m, nil
						}
						m.unlockStage = 1
						m.confirmInput.Focus()
						m.err = nil
						return m, nil
					} else {
						if m.passwordInput.Value() != m.confirmInput.Value() {
							m.err = fmt.Errorf("passwords do not match")
							m.unlockStage = 0
							m.passwordInput.SetValue("")
							m.confirmInput.SetValue("")
							m.passwordInput.Focus()
							return m, nil
						}
						pass := []byte(m.passwordInput.Value())
						key, err := m.store.SetupEncryption(pass)
						// pass is zeroed by SetupEncryption
						if err != nil {
							m.err = err
							return m, nil
						}
						m.err = nil
						m.mode = ModeWelcome
						// Capture dataKey copy for background snapshots
						m.dataKey = make([]byte, len(key))
						copy(m.dataKey, key)
						crypto.Zero(key)
						m.entries, m.err = m.store.GetEntries()
						return m, nil
					}
				} else {
					pass := []byte(m.passwordInput.Value())
					dataKey, err := m.store.Unlock(pass)
					if err != nil {
						m.err = err
						m.passwordInput.SetValue("")
						return m, nil
					}
					m.store.SetKey(dataKey)
					m.dataKey = make([]byte, len(dataKey))
					copy(m.dataKey, dataKey)
					crypto.Zero(dataKey)
					m.err = nil
					m.mode = ModeWelcome
					m.entries, m.err = m.store.GetEntries()
					return m, nil
				}
			}

			var cmd tea.Cmd
			if m.unlockStage == 0 {
				m.passwordInput, cmd = m.passwordInput.Update(msg)
			} else {
				m.confirmInput, cmd = m.confirmInput.Update(msg)
			}
			cmds = append(cmds, cmd)
			return m, tea.Batch(cmds...)
		}

		if m.mode == ModeChangePassword {
			switch msg.String() {
			case "esc":
				m.mode = ModeSurface
				return m, nil
			case "enter":
				if m.changePassStage == 0 {
					currentPass := []byte(m.currentPassInput.Value())
					discardedKey, err := m.store.Unlock(currentPass)
					if discardedKey != nil {
						crypto.Zero(discardedKey)
					}
					if err != nil {
						m.err = err
						m.currentPassInput.SetValue("")
						return m, nil
					}
					m.err = nil
					m.changePassStage = 1
					m.passwordInput.Placeholder = "New Password"
					m.passwordInput.Focus()
					m.passwordInput.SetValue("")
				} else if m.changePassStage == 1 {
					if m.passwordInput.Value() == "" {
						m.err = fmt.Errorf("password cannot be empty")
						return m, nil
					}
					m.err = nil
					m.changePassStage = 2
					m.confirmInput.Focus()
					m.confirmInput.SetValue("")
				} else {
					if m.passwordInput.Value() != m.confirmInput.Value() {
						m.err = fmt.Errorf("passwords do not match")
						m.changePassStage = 1
						m.passwordInput.SetValue("")
						m.confirmInput.SetValue("")
						m.passwordInput.Focus()
						return m, nil
					}
					currentPass := []byte(m.currentPassInput.Value())
					newPass := []byte(m.passwordInput.Value())
					newKey, err := m.store.ChangePassword(currentPass, newPass)
					// currentPass and newPass are zeroed by ChangePassword
					if err != nil {
						m.err = err
						return m, nil
					}
					// Update m.dataKey for background snapshots using new key returned
					if m.dataKey != nil {
						crypto.Zero(m.dataKey)
					}
					m.dataKey = newKey
					m.err = nil
					m.mode = ModeSurface
					return m, nil
				}
				return m, nil
			}
			var cmd tea.Cmd
			if m.changePassStage == 0 {
				m.currentPassInput, cmd = m.currentPassInput.Update(msg)
			} else if m.changePassStage == 1 {
				m.passwordInput, cmd = m.passwordInput.Update(msg)
			} else {
				m.confirmInput, cmd = m.confirmInput.Update(msg)
			}
			cmds = append(cmds, cmd)
			return m, tea.Batch(cmds...)
		}

		if msg.String() == "ctrl+t" {
			m.themeIndex = (m.themeIndex + 1) % len(ui.Themes)
			m.styles = ui.GetStyles(ui.Themes[m.themeIndex])
			return m, nil
		}

		if msg.String() == "ctrl+p" && m.mode == ModeSurface {
			enabled, _ := m.store.IsEncryptionEnabled()
			if !enabled {
				// User is in plaintext mode, let them setup encryption
				m.isFirstRun = true
				m.mode = ModeUnlock
				m.unlockStage = 0
				m.passwordInput.Focus()
				m.passwordInput.SetValue("")
				m.confirmInput.SetValue("")
				m.passwordInput.Placeholder = "Set a Master Password"
				m.err = nil
				return m, nil
			}
			m.mode = ModeChangePassword
			m.changePassStage = 0
			m.currentPassInput.Focus()
			m.currentPassInput.SetValue("")
			m.passwordInput.SetValue("")
			m.confirmInput.SetValue("")
			m.err = nil
			return m, nil
		}

		if m.mode == ModeWelcome {
			switch keyStr {
			case "m":
				meta, err := m.store.GetArchiveMeta()
				if err == nil {
					m.archiveMeta = meta
					m.prevMode = m.mode
					m.mode = ModeArchiveMeta
					m.err = nil
				} else {
					m.err = err
				}
				return m, nil
			case "enter", " ":
				m.createNewEntry()
				m.mode = ModeDive
				m.updateLayout()
			case "tab":
				m.entries, m.err = m.store.GetEntries()
				m.mode = ModeSurface
				m.updateLayout()
			}
			return m, nil
		}

		if m.mode == ModeSurface {
			if m.searching {
				switch msg.String() {
				case "enter", "esc":
					m.searching = false
					m.searchInput.Blur()
					if msg.String() == "enter" && m.searchInput.Value() != "" {
						m.entries, m.err = m.store.SearchEntries(m.searchInput.Value())
					} else {
						m.entries, m.err = m.store.GetEntries()
					}
					m.cursorIndex = 0
				default:
					var cmd tea.Cmd
					m.searchInput, cmd = m.searchInput.Update(msg)
					cmds = append(cmds, cmd)
					if m.searchInput.Value() != "" {
						m.entries, m.err = m.store.SearchEntries(m.searchInput.Value())
					} else {
						m.entries, m.err = m.store.GetEntries()
					}
				}
				return m, tea.Batch(cmds...)
			}

			// Not searching: check for 'm'
			if keyStr == "m" {
				meta, err := m.store.GetArchiveMeta()
				if err == nil {
					m.archiveMeta = meta
					m.prevMode = m.mode
					m.mode = ModeArchiveMeta
					m.err = nil
				} else {
					m.err = err
				}
				return m, nil
			}

			if m.confirmingDelete {
				key := strings.ToLower(msg.String())
				if key == "y" {
					if m.cursorIndex > 0 && m.cursorIndex <= len(m.entries) {
						targetID := m.entries[m.cursorIndex-1].ID
						if m.entry != nil && m.entry.ID == targetID {
							m.createNewEntry()
						}
						m.err = m.store.DeleteEntry(targetID)
						if m.err == nil {
							m.entries, m.err = m.store.GetEntries()
							if m.cursorIndex > len(m.entries) {
								m.cursorIndex = len(m.entries)
							}
						}
					}
				}
				m.confirmingDelete = false
				return m, nil
			}

			switch msg.String() {
			case "up":
				if m.cursorIndex > 0 { m.cursorIndex-- }
			case "down":
				if m.cursorIndex < len(m.entries) { m.cursorIndex++ }
			case "/":
				m.searching = true
				m.searchInput.Focus()
				m.searchInput.SetValue("")
				return m, textinput.Blink
			case "x", "backspace":
				if m.cursorIndex > 0 { m.confirmingDelete = true }
			case "enter":
				if m.cursorIndex == 0 {
					m.createNewEntry()
				} else {
					m.loadEntry(m.entries[m.cursorIndex-1].ID)
				}
				m.mode = ModeDive
				m.updateLayout()
			case "tab":
				m.mode = ModeDive
				m.updateLayout()
			}
			return m, nil
		}

		m.lastInput = time.Now()
		m.dirty = true
		switch msg.String() {
		case "tab":
			m.save()
			m.entries, m.err = m.store.GetEntries()
			if m.entry != nil {
				trigs, err := m.store.GetLatestTriggers(m.entry.ID)
				if err != nil { m.err = err } else { m.triggers = trigs }
			}
			m.cursorIndex = 0
			m.mode = ModeSurface
			m.updateLayout()
		}

	case tickMsg:
		if m.dataKey != nil && m.mode != ModeUnlock {
			if time.Since(m.lastInput) >= time.Duration(m.config.AutoLockMinutes)*time.Minute {
				return m.performLock()
			}
		}

		if time.Since(m.lastInput) < 30*time.Second {
			if m.session != nil { m.session.ElapsedActive += time.Second }
		}
		cmds = append(cmds, tick())

	case autosaveMsg:
		if m.dirty {
			m.save()
			m.dirty = false
			if m.entry != nil {
				trigs, err := m.store.GetLatestTriggers(m.entry.ID)
				if err != nil { m.err = err } else { m.triggers = trigs }
			}
		}
		cmds = append(cmds, m.autosave())
	}

	if m.mode == ModeDive {
		var cmd tea.Cmd
		m.editor, cmd = m.editor.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
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

	ew := m.width - 8
	if m.mode == ModeSurface {
		ew = m.width - 45 // 36 (HUD) + padding/gutters
	}
	
	if ew < 20 { ew = 20 } // Minimum readable width
	
	m.editor.SetWidth(ew)
	m.editor.SetHeight(m.height - 10)
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
	trigs := parser.ScanContent(m.entry.ID, m.session.ID, body)
	
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

func (m Model) View() string {
	if m.width == 0 { return "Initializing..." }

	if m.mode == ModeUnlock {
		heading := m.styles.Title.Render("MNEMOSYNE")
		var sub string
		if m.isFirstRun {
			sub = m.styles.Label.Render("set a master password to encrypt your archive")
		} else {
			sub = m.styles.Label.Render("enter your master password to continue")
		}

		var input string
		if m.isFirstRun && m.unlockStage == 1 {
			input = m.confirmInput.View()
		} else {
			input = m.passwordInput.View()
		}

		var errView string
		if m.err != nil {
			errView = m.styles.ErrorMsg.Render(m.err.Error())
		}

		inner := lipgloss.JoinVertical(lipgloss.Left, heading, sub, "", input, errView)
		box := m.styles.Modal.Render(inner)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
	}

	if m.mode == ModeChangePassword {
		heading := m.styles.Title.Render("CHANGE PASSWORD")
		var sub string
		var input string

		if m.changePassStage == 0 {
			sub = m.styles.Label.Render("enter current password")
			input = m.currentPassInput.View()
		} else if m.changePassStage == 1 {
			sub = m.styles.Label.Render("enter new password")
			input = m.passwordInput.View()
		} else {
			sub = m.styles.Label.Render("confirm new password")
			input = m.confirmInput.View()
		}

		var errView string
		if m.err != nil {
			errView = m.styles.ErrorMsg.Render(m.err.Error())
		}

		inner := lipgloss.JoinVertical(lipgloss.Left, heading, sub, "", input, errView)
		box := m.styles.Modal.Render(inner)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
	}

	if m.mode == ModeArchiveMeta && m.archiveMeta != nil {
		meta := m.archiveMeta
		heading := lipgloss.JoinVertical(lipgloss.Left,
			m.styles.Title.Render("M N E M O S Y N E"),
			m.styles.Label.Render("archive meta  ·  "+time.Now().Format("Monday, Jan 02")),
		)

		rule := m.styles.Divider.Render(strings.Repeat("─", 44))

		row := func(label, value string) string {
			return lipgloss.JoinHorizontal(lipgloss.Top,
				m.styles.Label.Copy().Width(24).Render(label),
				m.styles.Value.Copy().Width(20).Align(lipgloss.Right).Render(value),
			)
		}

		// Section 1: The Weight
		activeH := meta.TotalActiveMs / 3600000
		activeM := (meta.TotalActiveMs % 3600000) / 60000
		activeStr := fmt.Sprintf("%dh %dm", activeH, activeM)
		span := fmt.Sprintf("%s – %s", meta.FirstEntryAt.Format("Jan 2006"), meta.LastEntryAt.Format("Jan 2006"))
		if meta.TotalEntries == 0 { span = "none" }

		weight := lipgloss.JoinVertical(lipgloss.Left,
			m.styles.SectionHead.Render("THE WEIGHT"),
			row("words", fmt.Sprintf("%d", meta.TotalWords)),
			row("entries", fmt.Sprintf("%d", meta.TotalEntries)),
			row("active time", activeStr),
			row("span", span),
		)

		// Section 2: The Rhythm
		mostActive := strings.ToLower(meta.MostActiveDay.String()) + "s"
		if meta.TotalEntries == 0 { mostActive = "none" }
		
		rhythm := lipgloss.JoinVertical(lipgloss.Left,
			m.styles.SectionHead.Render("THE RHYTHM"),
			row("streak", fmt.Sprintf("%d days", meta.CurrentStreak)),
			row("longest", fmt.Sprintf("%d days", meta.LongestStreak)),
			row("avg entry", fmt.Sprintf("%d words", meta.AvgWordsPerEntry)),
			row("most active", mostActive),
		)

		// Section 3: Top Signals
		var signals strings.Builder
		signals.WriteString(m.styles.SectionHead.Render("TOP SIGNALS") + "\n")
		if len(meta.TopTriggers) == 0 {
			signals.WriteString(m.styles.Label.Render("none recorded"))
		} else {
			for _, t := range meta.TopTriggers {
				signals.WriteString(row(t.Prefix+":", fmt.Sprintf("%d", t.Count)) + "\n")
			}
		}

		content := lipgloss.JoinVertical(lipgloss.Left,
			heading, "", rule, "",
			weight, "",
			rhythm, "",
			signals.String(), "",
			rule, "",
			m.styles.Label.Render("                               [esc] close"),
		)

		box := m.styles.Modal.Width(52).Render(content)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
	}

	if m.mode == ModeWelcome {
		dw := m.width / 3
		if dw > 28 { dw = 28 }
		divider := m.styles.Divider.Render(strings.Repeat("─", dw))

		wordmark := lipgloss.JoinVertical(lipgloss.Center,
			m.styles.Title.Render("M N E M O S Y N E"),
			m.styles.Label.Render("a personal memory palace"),
		)

		date := m.styles.Welcome.Render(time.Now().Format("Monday, January 02"))

		var lastWrite string
		if len(m.entries) > 0 {
			last := m.entries[0]
			lastWrite = m.styles.Label.Render(
				fmt.Sprintf("last entry: %s · %d words",
					last.CreatedAt.Format("Jan 02"), last.WordCount))
		} else {
			lastWrite = m.styles.Label.Render("the archive is empty")
		}

		hint := func(key, label string) string {
			return fmt.Sprintf("%s  %s", m.styles.Trigger.Render(key), m.styles.Label.Render(label))
		}

		errView := ""
		if m.err != nil {
			errView = "\n" + m.styles.ErrorMsg.Render(m.err.Error())
		}

		content := lipgloss.JoinVertical(lipgloss.Center, wordmark, "", divider, "", date, lastWrite, "", divider, "", hint("enter", "begin a new dive"), hint("tab  ", "surface the archive"), hint("m    ", "archive meta"), errView)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, content)
	}

	if m.mode == ModeSurface {
		ruleWidth := 28
		rule := m.styles.Divider.Render(strings.Repeat("─", ruleWidth))
		var hb strings.Builder

		hb.WriteString(m.styles.Title.Render("MNEMOSYNE") + "\n")
		hb.WriteString(m.styles.Label.Render(time.Now().Format("Mon Jan 02")) + "\n\n")
		hb.WriteString(rule + "\n\n")

		wc := len(strings.Fields(m.editor.Value()))
		at := time.Duration(0)
		if m.session != nil { at = m.session.ElapsedActive }

		hb.WriteString(m.styles.SectionHead.Render("SESSION") + "\n")
		hb.WriteString(m.styles.Label.Render("words   ") + m.styles.Value.Render(fmt.Sprintf("%d", wc)) + "\n")
		hb.WriteString(m.styles.Label.Render("active  ") + m.styles.Value.Render(at.Round(time.Second).String()) + "\n")
		if !m.lastSave.IsZero() { hb.WriteString(m.styles.Label.Render("saved   ") + m.styles.Value.Render(m.lastSave.Format("15:04:05")) + "\n") }
		hb.WriteString("\n" + rule + "\n\n")

		if len(m.triggers) > 0 {
			hb.WriteString(m.styles.SectionHead.Render("METRICS") + "\n")
			for _, t := range m.triggers {
				payload := t.Payload
				if len([]rune(payload)) > 20 {
					payload = string([]rune(payload)[:17]) + "..."
				}
				hb.WriteString(m.styles.Trigger.Render(t.Prefix+":") + " " + payload + "\n")
			}
			hb.WriteString("\n" + rule + "\n\n")
		}

		if m.searching {
			hb.WriteString(m.styles.SectionHead.Render("SEARCH") + "\n")
			hb.WriteString(m.searchInput.View() + "\n\n")
		} else {
			hb.WriteString(m.styles.SectionHead.Render("HISTORY") + "  " + m.styles.Label.Render("[/ to search]") + "\n\n")
		}

		if m.confirmingDelete { hb.WriteString(m.styles.ErrorMsg.Render("DELETE? (y/n)") + "\n") }
		if m.cursorIndex == 0 { hb.WriteString(m.styles.EntrySelected.Render("▸ + new entry") + "\n") } else { hb.WriteString(m.styles.EntryNormal.Render("  + new entry") + "\n") }
		
		for i, e := range m.entries {
			if i == 10 {
				hb.WriteString(m.styles.Label.Render(fmt.Sprintf("  +%d more...", len(m.entries)-10)) + "\n")
				break
			}
			title := e.Title
			if title == "" { title = "Untitled" }
			r := []rune(title)
			if len(r) > 20 { title = string(r[:17]) + "..." }
			line := fmt.Sprintf("%s · %s", e.CreatedAt.Format("01/02"), title)
			if m.cursorIndex == i+1 {
				hb.WriteString(m.styles.EntrySelected.Render("▸ "+line) + "\n")
			} else {
				hb.WriteString(m.styles.EntryNormal.Render("  "+line) + "\n")
			}
		}
		
		hv := m.styles.HUD.Height(m.height - 6).Render(hb.String())
		ev := m.styles.Editor.Render(m.editor.View())
		return m.styles.Main.Render(lipgloss.JoinHorizontal(lipgloss.Top, ev, hv))
	}

	var saveStr string
	if !m.lastSave.IsZero() { saveStr = " · " + m.lastSave.Format("15:04") }
	wc := len(strings.Fields(m.editor.Value()))
	at := time.Duration(0)
	if m.session != nil { at = m.session.ElapsedActive }
	statusLine := m.styles.StatusBar.Render(strings.Join([]string{m.styles.Value.Render(fmt.Sprintf("%d words", wc)), m.styles.Label.Render(at.Round(time.Second).String() + saveStr)}, "  ·  "))
	hints := m.styles.StatusBar.Render("[tab] surface  [m] meta  [ctrl+l] lock  [ctrl+t] theme  [ctrl+p] password")
	ev := m.styles.Editor.Render(m.editor.View())
	return m.styles.Main.Render(lipgloss.JoinVertical(lipgloss.Left, ev, statusLine, hints))
}
