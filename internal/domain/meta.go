package domain

import "time"

type ArchiveMeta struct {
	TotalEntries     int
	TotalWords       int
	TotalActiveMs    int64
	FirstEntryAt     time.Time
	LastEntryAt      time.Time
	CurrentStreak    int
	LongestStreak    int
	AvgWordsPerEntry int
	MostActiveDay    time.Weekday
	TopTriggers      []TriggerStat
}

type TriggerStat struct {
	Prefix string
	Count  int
}
