package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

func (m Model) View() string {
	if m.width == 0 {
		return "Initializing..."
	}

	// Helper to calculate modal width based on window size
	getModalWidth := func(base int) int {
		if m.width-10 < base {
			return m.width - 10
		}
		return base
	}

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
		box := m.styles.Modal.Width(getModalWidth(44)).Render(inner)
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
		box := m.styles.Modal.Width(getModalWidth(44)).Render(inner)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
	}

	if m.mode == ModeArchiveMeta && m.archiveMeta != nil {
		meta := m.archiveMeta
		heading := lipgloss.JoinVertical(lipgloss.Left,
			m.styles.Title.Render("M N E M O S Y N E"),
			m.styles.Label.Render("archive meta  ·  "+time.Now().Format("Monday, Jan 02")),
		)

		mw := getModalWidth(52)
		rule := m.styles.Divider.Render(strings.Repeat("─", mw-8))

		row := func(label, value string) string {
			return lipgloss.JoinHorizontal(lipgloss.Top,
				m.styles.Label.Copy().Width(mw/2-2).Render(label),
				m.styles.Value.Copy().Width(mw/2-2).Align(lipgloss.Right).Render(value),
			)
		}

		// Section 1: The Weight
		activeH := meta.TotalActiveMs / 3600000
		activeM := (meta.TotalActiveMs % 3600000) / 60000
		activeStr := fmt.Sprintf("%dh %dm", activeH, activeM)
		span := fmt.Sprintf("%s – %s", meta.FirstEntryAt.Format("Jan 2006"), meta.LastEntryAt.Format("Jan 2006"))
		if meta.TotalEntries == 0 {
			span = "none"
		}

		weight := lipgloss.JoinVertical(lipgloss.Left,
			m.styles.SectionHead.Render("THE WEIGHT"),
			row("words", fmt.Sprintf("%d", meta.TotalWords)),
			row("entries", fmt.Sprintf("%d", meta.TotalEntries)),
			row("active time", activeStr),
			row("span", span),
		)

		// Section 2: The Rhythm
		mostActive := strings.ToLower(meta.MostActiveDay.String()) + "s"
		if meta.TotalEntries == 0 {
			mostActive = "none"
		}

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

		box := m.styles.Modal.Width(mw).Render(content)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
	}

	if m.mode == ModeWelcome {
		dw := m.width / 3
		if dw > 28 {
			dw = 28
		}
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
		showEditor := true
		hudWidth := 36
		if m.width < 72 {
			hudWidth = m.width - 20 - 8 // Preserve minimum editor width
		}
		if hudWidth < 30 {
			hudWidth = 30
		}
		if m.width <= 58 {
			showEditor = false
			hudWidth = m.width - 6
		}

		ruleWidth := hudWidth - 8
		if ruleWidth < 10 {
			ruleWidth = 10
		}
		rule := m.styles.Divider.Render(strings.Repeat("─", ruleWidth))
		var hb strings.Builder

		hb.WriteString(m.styles.Title.Render("MNEMOSYNE") + "\n")
		hb.WriteString(m.styles.Label.Render(time.Now().Format("Mon Jan 02")) + "\n")

		// Compact view for small heights
		spacer := "\n"
		if m.height < 24 {
			spacer = ""
		}

		hb.WriteString(spacer + "\n" + rule + "\n" + spacer)

		wc := len(strings.Fields(m.editor.Value()))
		at := time.Duration(0)
		if m.session != nil {
			at = m.session.ElapsedActive
		}

		hb.WriteString(m.styles.SectionHead.Render("SESSION") + "\n")
		hb.WriteString(m.styles.Label.Render("words   ") + m.styles.Value.Render(fmt.Sprintf("%d", wc)) + "\n")
		hb.WriteString(m.styles.Label.Render("active  ") + m.styles.Value.Render(at.Round(time.Second).String()) + "\n")
		if !m.lastSave.IsZero() {
			hb.WriteString(m.styles.Label.Render("saved   ") + m.styles.Value.Render(m.lastSave.Format("15:04:05")) + "\n")
		}
		hb.WriteString(spacer + "\n" + rule + "\n" + spacer)

		if len(m.triggers) > 0 {
			hb.WriteString(m.styles.SectionHead.Render("METRICS") + "\n")
			innerHUDWidth := hudWidth - 6
			for _, t := range m.triggers {
				prefix := t.Prefix + ":"
				maxPayload := innerHUDWidth - len(prefix) - 1
				if maxPayload < 5 {
					maxPayload = 5
				}
				payload := t.Payload
				if len([]rune(payload)) > maxPayload {
					payload = string([]rune(payload)[:maxPayload-3]) + "..."
				}
				hb.WriteString(m.styles.Trigger.Render(prefix) + " " + payload + "\n")
			}
			hb.WriteString(spacer + "\n" + rule + "\n" + spacer)
		}

		if m.searching {
			hb.WriteString(m.styles.SectionHead.Render("SEARCH") + "\n")
			hb.WriteString(m.searchInput.View() + "\n" + spacer)
		} else {
			hb.WriteString(m.styles.SectionHead.Render("HISTORY") + "  " + m.styles.Label.Render("[/]") + "\n")
		}

		if m.confirmingDelete {
			hb.WriteString(m.styles.ErrorMsg.Render("DELETE? (y/n)") + "\n")
		}
		if m.cursorIndex == 0 {
			hb.WriteString(m.styles.EntrySelected.Render("▸ + new entry") + "\n")
		} else {
			hb.WriteString(m.styles.EntryNormal.Render("  + new entry") + "\n")
		}

		for i, e := range m.entries {
			if i == 10 {
				hb.WriteString(m.styles.Label.Render(fmt.Sprintf("  +%d more...", len(m.entries)-10)) + "\n")
				break
			}
			title := e.Title
			if title == "" {
				title = "Untitled"
			}
			
			innerHUDWidth := hudWidth - 10
			if innerHUDWidth < 10 { innerHUDWidth = 10 }
			r := []rune(title)
			if len(r) > innerHUDWidth {
				title = string(r[:innerHUDWidth-3]) + "..."
			}
			line := fmt.Sprintf("%s · %s", e.CreatedAt.Format("01/02"), title)
			if m.cursorIndex == i+1 {
				hb.WriteString(m.styles.EntrySelected.Render("▸ "+line) + "\n")
			} else {
				hb.WriteString(m.styles.EntryNormal.Render("  "+line) + "\n")
			}
		}

		hv := m.styles.HUD.Width(hudWidth).Height(m.height - 6).Render(hb.String())
		if showEditor {
			ev := m.styles.Editor.Render(m.editor.View())
			return m.styles.Main.Render(lipgloss.JoinHorizontal(lipgloss.Top, ev, hv))
		}
		return m.styles.Main.Render(hv)
	}

	var saveStr string
	if !m.lastSave.IsZero() {
		saveStr = " · " + m.lastSave.Format("15:04")
	}
	wc := len(strings.Fields(m.editor.Value()))
	at := time.Duration(0)
	if m.session != nil {
		at = m.session.ElapsedActive
	}
	statusLine := m.styles.StatusBar.Render(strings.Join([]string{m.styles.Value.Render(fmt.Sprintf("%d words", wc)), m.styles.Label.Render(at.Round(time.Second).String() + saveStr)}, "  ·  "))
	hints := m.styles.StatusBar.Render("[tab] surface  [m] meta  [ctrl+l] lock  [ctrl+t] theme  [ctrl+p] password")
	ev := m.styles.Editor.Render(m.editor.View())
	return m.styles.Main.Render(lipgloss.JoinVertical(lipgloss.Left, ev, statusLine, hints))
}
