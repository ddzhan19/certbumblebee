package main

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

type jobStep struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	State string `json:"state"` // wait | run | ok | fail
	Note  string `json:"note"`
}

// Job ist ein Hintergrundvorgang, dessen Fortschritt die Oberfläche abfragt. Er ist zugleich ein Reporter.
type Job struct {
	ID        string
	ProfileID string
	mu        sync.Mutex
	steps     []*jobStep
	logLines  []string
	state     string // run | ok | error
	message   string
	detail    string
	result    any
	created   time.Time
}

type jobView struct {
	ID      string     `json:"id"`
	State   string     `json:"state"`
	Steps   []*jobStep `json:"steps"`
	Log     []string   `json:"log"`
	Message string     `json:"message,omitempty"`
	Detail  string     `json:"detail,omitempty"`
	Result  any        `json:"result,omitempty"`
}

var (
	jobsMu sync.Mutex
	jobs   = map[string]*Job{}
)

func newJob(profileID string) *Job {
	j := &Job{ID: randomHex(8), ProfileID: profileID, state: "run", created: time.Now()}
	jobsMu.Lock()
	for id, o := range jobs {
		if time.Since(o.created) > 2*time.Hour {
			delete(jobs, id)
		}
	}
	jobs[j.ID] = j
	jobsMu.Unlock()
	return j
}

func getJob(id string) *Job {
	jobsMu.Lock()
	defer jobsMu.Unlock()
	return jobs[id]
}

func (j *Job) find(key string) *jobStep {
	for _, s := range j.steps {
		if s.Key == key {
			return s
		}
	}
	return nil
}

func (j *Job) Declare(key, label string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if s := j.find(key); s != nil {
		s.Label = label
		return
	}
	j.steps = append(j.steps, &jobStep{Key: key, Label: label, State: "wait"})
}

func (j *Job) Step(key, label string) {
	j.mu.Lock()
	s := j.find(key)
	if s == nil {
		s = &jobStep{Key: key}
		j.steps = append(j.steps, s)
	}
	s.Label, s.State, s.Note = label, "run", ""
	j.mu.Unlock()
	appLog(j.ProfileID, "INFO", label)
}

func (j *Job) Note(key, note string) {
	j.mu.Lock()
	if s := j.find(key); s != nil {
		s.Note = note
	}
	j.mu.Unlock()
	appLog(j.ProfileID, "INFO", note)
}

func (j *Job) Ok(key, note string) {
	j.mu.Lock()
	if s := j.find(key); s != nil {
		s.State = "ok"
		if note != "" {
			s.Note = note
		}
	}
	j.mu.Unlock()
}

func (j *Job) Fail(key, msg string) {
	j.mu.Lock()
	if s := j.find(key); s != nil {
		s.State, s.Note = "fail", msg
	}
	j.mu.Unlock()
	appLog(j.ProfileID, "ERROR", msg)
}

func (j *Job) Logf(format string, a ...any) {
	line := fmt.Sprintf(format, a...)
	j.mu.Lock()
	j.logLines = append(j.logLines, time.Now().Format("15:04:05")+"  "+line)
	j.mu.Unlock()
	appLog(j.ProfileID, "INFO", line)
}

func (j *Job) finish(err error, result any) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err != nil {
		j.state = "error"
		j.message = err.Error()
		var ue *userError
		if errors.As(err, &ue) {
			j.detail = ue.Tech
		}
		return
	}
	j.state = "ok"
	j.result = result
}

func (j *Job) view() jobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	steps := make([]*jobStep, len(j.steps))
	for i, s := range j.steps {
		c := *s
		steps[i] = &c
	}
	return jobView{ID: j.ID, State: j.state, Steps: steps, Log: append([]string(nil), j.logLines...), Message: j.message, Detail: j.detail, Result: j.result}
}

// consoleReporter schreibt Fortschritt auf die Konsole (für den Aufruf „renew“).
type consoleReporter struct{ id string }

func (c consoleReporter) Declare(key, label string) {}
func (c consoleReporter) Step(key, label string) {
	fmt.Fprintln(os.Stdout, "==> "+label)
	appLog(c.id, "INFO", label)
}
func (c consoleReporter) Note(key, note string) {
	fmt.Fprintln(os.Stdout, "    "+note)
	appLog(c.id, "INFO", note)
}
func (c consoleReporter) Ok(key, note string) {
	if note != "" {
		fmt.Fprintln(os.Stdout, "    "+note)
	}
}
func (c consoleReporter) Fail(key, msg string) {
	fmt.Fprintln(os.Stderr, "FEHLER: "+msg)
	appLog(c.id, "ERROR", msg)
}
func (c consoleReporter) Logf(format string, a ...any) {
	line := fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stdout, "    "+line)
	appLog(c.id, "INFO", line)
}
