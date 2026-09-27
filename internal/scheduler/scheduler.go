// Package scheduler implements the daily kill switch.
package scheduler

import (
	"context"
	"time"

	"github.com/ruepp-jenkins/sunshine-gw/internal/control"
	"github.com/ruepp-jenkins/sunshine-gw/internal/events"
)

type Scheduler struct {
	ctrl *control.Controller
	log  *events.Log
	// now is overridable so the timer arithmetic can be tested without waiting for a
	// wall-clock minute to pass.
	now func() time.Time
}

func New(ctrl *control.Controller, log *events.Log) *Scheduler {
	return &Scheduler{ctrl: ctrl, log: log, now: time.Now}
}

// Run waits for the next daily off time and switches the forwarding off when it
// arrives. It recomputes whenever the configuration changes, so a new time takes
// effect immediately. The next occurrence is derived from time.Date in the configured
// location rather than by adding 24 h, which keeps DST transitions correct.
func (s *Scheduler) Run(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	for {
		st := s.ctrl.State()
		now := s.now()
		next := st.NextOffTime(now)
		var wait <-chan time.Time
		if next.IsZero() {
			// No daily off time configured: only wake up on a configuration change.
			wait = nil
		} else {
			d := next.Sub(now)
			if d < time.Second {
				d = time.Second
			}
			timer.Reset(d)
			wait = timer.C
			if st.Enabled {
				s.log.Infof("naechste automatische Abschaltung: %s", next.Format("02.01. 15:04 MST"))
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-s.ctrl.Reload():
			if wait != nil && !timer.Stop() {
				// Drain a timer that fired while we were re-reading the config.
				select {
				case <-timer.C:
				default:
				}
			}
		case <-wait:
			cur := s.ctrl.State()
			if !cur.Enabled {
				continue
			}
			if err := s.ctrl.SetEnabled(false, "taegliche Abschaltung um "+cur.DailyOffTime); err != nil {
				s.log.Errorf("automatische Abschaltung fehlgeschlagen: %v", err)
			}
		}
	}
}
