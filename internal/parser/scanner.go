package parser

import (
	"bufio"
	"bytes"
	"mnemosyne/internal/domain"
	"strings"
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

func ScanContent(entryID int64, sessionID int64, content string) ([]domain.Trigger, error) {
	var triggers []domain.Trigger
	scanner := bufio.NewScanner(strings.NewReader(content))

	// Increase buffer limit to 1MiB for exceptionally long lines
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineNo := 1
	for scanner.Scan() {
		if t, ok := ScanLine(lineNo, entryID, sessionID, scanner.Bytes()); ok {
			triggers = append(triggers, *t)
		}
		lineNo++
	}

	return triggers, scanner.Err()
}
