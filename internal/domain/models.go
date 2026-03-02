package domain

import "time"

type Entry struct {
	ID        int64     `json:"id"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	WordCount int       `json:"word_count"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type WritingSession struct {
	ID               int64         `json:"id"`
	EntryID          int64         `json:"entry_id"`
	StartedAt        time.Time     `json:"started_at"`
	EndedAt          *time.Time    `json:"ended_at"`
	ElapsedActive    time.Duration `json:"elapsed_active"`
	WordsAdded       int           `json:"words_added"`
}

type Trigger struct {
	ID        int64     `json:"id"`
	EntryID   int64     `json:"entry_id"`
	SessionID int64     `json:"session_id"`
	LineNo    int       `json:"line_no"`
	Prefix    string    `json:"prefix"`
	Payload   string    `json:"payload"`
	CreatedAt time.Time `json:"created_at"`
}
