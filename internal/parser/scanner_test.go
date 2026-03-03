package parser

import (
	"testing"
)

func TestScanContent(t *testing.T) {
	content := `This is a test.
MOOD: excited
ENERGY: high
Some other text.
TAG: focus
EMPTY: 
INVALID:lowercase
NOT A TRIGGER
STILL: good`

	triggers := ScanContent(1, 1, content)

	expected := []struct {
		Prefix  string
		Payload string
		LineNo  int
	}{
		{"MOOD", "excited", 2},
		{"ENERGY", "high", 3},
		{"TAG", "focus", 5},
		{"EMPTY", "", 6},
		{"INVALID", "lowercase", 7},
		{"STILL", "good", 9},
	}

	if len(triggers) != len(expected) {
		t.Fatalf("expected %d triggers, got %d", len(expected), len(triggers))
	}

	for i, trig := range triggers {
		if trig.Prefix != expected[i].Prefix {
			t.Errorf("trigger %d: expected prefix %q, got %q", i, expected[i].Prefix, trig.Prefix)
		}
		if trig.Payload != expected[i].Payload {
			t.Errorf("trigger %d: expected payload %q, got %q", i, expected[i].Payload, trig.Payload)
		}
		if trig.LineNo != expected[i].LineNo {
			t.Errorf("trigger %d: expected line %d, got %d", i, expected[i].LineNo, trig.LineNo)
		}
	}
}

func TestScanLine(t *testing.T) {
	tests := []struct {
		input    string
		prefix   string
		payload  string
		expected bool
	}{
		{"MOOD: happy", "MOOD", "happy", true},
		{"ENERGY: 5/10", "ENERGY", "5/10", true},
		{"lowercase: no", "", "", false},
		{"NO SPACE:yes", "NO", "SPACE:yes", false}, // Currently "NO" because it stops at space? No, wait.
		// Let's check the code: line[i] >= 'A' && line[i] <= 'Z'.
		// "NO SPACE:yes" -> ' ' is not A-Z. So i stops at 2. line[2] is ' '. line[2] != ':'. Returns false.
		{"MIXEDcase: no", "", "", false},
		{"TRIGGER:   trimmed   ", "TRIGGER", "trimmed", true},
		{"  LEADSPACE: ok", "LEADSPACE", "ok", true},
		{":noprefix", "", "", false},
		{"NO_UNDERSCORE: no", "", "", false}, // '_' not in A-Z
	}

	for _, tt := range tests {
		trig, ok := ScanLine(1, 1, 1, []byte(tt.input))
		if ok != tt.expected {
			t.Errorf("input %q: expected ok=%v, got %v", tt.input, tt.expected, ok)
			continue
		}
		if ok {
			if trig.Prefix != tt.prefix {
				t.Errorf("input %q: expected prefix %q, got %q", tt.input, tt.prefix, trig.Prefix)
			}
			if trig.Payload != tt.payload {
				t.Errorf("input %q: expected payload %q, got %q", tt.input, tt.payload, trig.Payload)
			}
		}
	}
}
