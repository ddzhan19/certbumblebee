package main

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Zeitplan im Dauerbetrieb („serve“): Jedes Zertifikat mit automatischer Erneuerung wird einmal am Tag zur eingestellten
// Uhrzeit geprüft. Ist das Programm zu dieser Zeit nicht gelaufen (Neustart, Wartung), wird der Lauf nachgeholt.
// Nach einem Fehler gibt es alle zwei Stunden einen neuen Versuch. Ist die Erneuerung nicht fällig, kostet der Lauf nichts.

const (
	schedTick       = 30 * time.Second
	schedRetryAfter = 2 * time.Hour
	schedRunLimit   = 90 * time.Minute
)

type scheduler struct {
	mu       sync.Mutex
	lastTick time.Time
	done     chan struct{}
	cancel   context.CancelFunc
	now      func() time.Time
	tick     time.Duration
}

func newScheduler() *scheduler {
	return &scheduler{lastTick: time.Now(), now: time.Now, tick: schedTick}
}

// dueNow sagt, ob für dieses Zertifikat jetzt ein Zeitplan-Lauf ansteht.
func dueNow(p *Profile, st State, now time.Time) bool {
	if !p.Task.Enabled {
		return false
	}
	var h, m int
	if _, err := fmt.Sscanf(p.Task.Time, "%d:%d", &h, &m); err != nil {
		return false
	}
	at := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
	if now.Before(at) {
		return false
	}
	if !st.AutoNext.IsZero() && now.Before(st.AutoNext) {
		return false
	}
	return st.AutoRunDay != now.Format("2006-01-02")
}

// recordAutoRun hält das Ergebnis eines Zeitplan-Laufs fest.
func recordAutoRun(id string, ok bool, now time.Time) {
	unlock, err := lockProfile(id)
	if err != nil {
		return
	}
	defer unlock()
	st := loadState(id)
	if ok {
		st.AutoRunDay, st.AutoNext = now.Format("2006-01-02"), time.Time{}
	} else {
		st.AutoNext = now.Add(schedRetryAfter)
	}
	_ = saveState(id, st)
}

// runDue führt alle fälligen Läufe nacheinander aus und meldet, wie viele es waren.
func (s *scheduler) runDue(ctx context.Context) int {
	n := 0
	for _, id := range listProfileIDs() {
		if ctx.Err() != nil {
			return n
		}
		s.beat()
		p, err := loadProfile(id)
		if err != nil || !dueNow(p, loadState(id), s.now()) {
			continue
		}
		n++
		appLog(id, "INFO", fmt.Sprintf("Zeitplan: Prüfung um %s fällig, starte.", p.Task.Time))
		rctx, cancel := context.WithTimeout(ctx, schedRunLimit)
		res, err := renewProfile(rctx, id, false, &collectReporter{id: id})
		cancel()
		if ctx.Err() != nil { // Programm wird beendet: kein Fehlversuch vermerken
			appLog(id, "INFO", "Zeitplan: Lauf wegen Beenden des Programms abgebrochen.")
			return n
		}
		if err != nil {
			appLog(id, "ERROR", "Zeitplan: "+err.Error())
			recordAutoRun(id, false, s.now())
			continue
		}
		appLog(id, "INFO", "Zeitplan: "+res.Message)
		recordAutoRun(id, true, s.now())
	}
	s.beat()
	return n
}

func (s *scheduler) beat() {
	s.mu.Lock()
	s.lastTick = time.Now()
	s.mu.Unlock()
}

// healthy: Die Schleife hat sich in den letzten 45 Minuten gemeldet (ein Lauf darf lange dauern).
func (s *scheduler) healthy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.lastTick) < 45*time.Minute
}

// start läuft im Hintergrund, bis stop aufgerufen wird.
func (s *scheduler) start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		appLogGlobal("Zeitplan gestartet (täglich zur eingestellten Uhrzeit, Zeitzone " + time.Now().Location().String() + ")")
		t := time.NewTicker(s.tick)
		defer t.Stop()
		s.runDue(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.runDue(ctx)
			}
		}
	}()
}

// stop bricht einen laufenden Vorgang ab und wartet höchstens so lange, bis aufgeräumt ist (DNS-Einträge löschen u. a.).
func (s *scheduler) stop(wait time.Duration) {
	if s.cancel == nil {
		return
	}
	s.cancel()
	select {
	case <-s.done:
	case <-time.After(wait):
	}
}
