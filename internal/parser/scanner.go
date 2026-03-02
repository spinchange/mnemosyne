package parser

import (
	"bytes"
	"mnemosyne/internal/domain"
	"time"
)

func ScanLine(lineNo int, entryID int64, sessionID int64, line []byte) (*domain.Trigger, bool) {
	line = bytes.TrimSpace(line)
	if len(line) < 2 {
		return nil, false
	}

	i := 0
	for i < len(line) && line[i] >= 'A' && line[i] <= 'Z' {
		i++
	}

	if i == 0 || i == len(line) || line[i] != ':' {
		return nil, false
	}

	prefix := string(line[:i])
	payload := string(bytes.TrimSpace(line[i+1:]))

	return &domain.Trigger{
		EntryID:   entryID,
		SessionID: sessionID,
		LineNo:    lineNo,
		Prefix:    prefix,
		Payload:   payload,
		CreatedAt: time.Now(),
	}, true
}

func ScanContent(entryID int64, sessionID int64, content string) []domain.Trigger {
	var triggers []domain.Trigger
	lines := bytes.Split([]byte(content), []byte("\n"))
	for i, line := range lines {
		if t, ok := ScanLine(i+1, entryID, sessionID, line); ok {
			triggers = append(triggers, *t)
		}
	}
	return triggers
}
