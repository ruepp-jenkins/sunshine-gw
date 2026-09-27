// Package events keeps the last few things that happened, for the web UI, and mirrors
// them to stderr so `docker logs` tells the same story.
package events

import (
	"fmt"
	"log"
	"sync"
	"time"
)

const maxEvents = 50

type Level string

const (
	Info  Level = "info"
	Warn  Level = "warn"
	Error Level = "error"
)

type Event struct {
	Time    time.Time `json:"time"`
	Level   Level     `json:"level"`
	Message string    `json:"message"`
}

type Log struct {
	mu     sync.Mutex
	events []Event
	logger *log.Logger
}

func New(logger *log.Logger) *Log {
	return &Log{logger: logger}
}

func (l *Log) add(level Level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l.mu.Lock()
	l.events = append(l.events, Event{Time: time.Now(), Level: level, Message: msg})
	if len(l.events) > maxEvents {
		l.events = l.events[len(l.events)-maxEvents:]
	}
	l.mu.Unlock()
	if l.logger != nil {
		l.logger.Printf("%-5s %s", level, msg)
	}
}

func (l *Log) Infof(format string, args ...any)  { l.add(Info, format, args...) }
func (l *Log) Warnf(format string, args ...any)  { l.add(Warn, format, args...) }
func (l *Log) Errorf(format string, args ...any) { l.add(Error, format, args...) }

// Recent returns the events newest first.
func (l *Log) Recent() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Event, 0, len(l.events))
	for i := len(l.events) - 1; i >= 0; i-- {
		out = append(out, l.events[i])
	}
	return out
}
