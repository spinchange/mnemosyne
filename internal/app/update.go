package app

import (
	"fmt"
	"mnemosyne/internal/crypto"
	"mnemosyne/internal/ui"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

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
				if m.cursorIndex > 0 {
					m.cursorIndex--
				}
			case "down":
				if m.cursorIndex < len(m.entries) {
					m.cursorIndex++
				}
			case "/":
				m.searching = true
				m.searchInput.Focus()
				m.searchInput.SetValue("")
				return m, textinput.Blink
			case "x", "backspace":
				if m.cursorIndex > 0 {
					m.confirmingDelete = true
				}
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
				if err != nil {
					m.err = err
				} else {
					m.triggers = trigs
				}
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
			if m.session != nil {
				m.session.ElapsedActive += time.Second
			}
		}
		cmds = append(cmds, tick())

	case autosaveMsg:
		if m.dirty {
			m.save()
			m.dirty = false
			if m.entry != nil {
				trigs, err := m.store.GetLatestTriggers(m.entry.ID)
				if err != nil {
					m.err = err
				} else {
					m.triggers = trigs
				}
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
