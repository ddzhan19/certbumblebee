package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var logMu sync.Mutex

// logStdout: Im Dauerbetrieb („serve“) geht jede Protokollzeile zusätzlich auf die Standardausgabe (docker logs).
var logStdout atomic.Bool

func logPath() string { return filepath.Join(dataDir(), "log", "za.log") }

// appLog schreibt eine Zeile ins Protokoll (best effort, nie ein Fehler nach außen).
func appLog(id, level, msg string) {
	logMu.Lock()
	defer logMu.Unlock()
	p := logPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	if fi, err := os.Stat(p); err == nil && fi.Size() > 1<<20 {
		_ = os.Remove(p + ".alt")
		_ = os.Rename(p, p+".alt")
	}
	msg = strings.NewReplacer("\r\n", " | ", "\n", " | ", "\r", " ").Replace(msg)
	if id == "" {
		id = "-"
	}
	line := fmt.Sprintf("%s [%s] [%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), level, id, msg)
	if logStdout.Load() {
		fmt.Fprint(os.Stdout, line)
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprint(f, line)
}

// appLogGlobal schreibt eine Zeile ohne Zuordnung zu einer Einrichtung.
func appLogGlobal(msg string) { appLog("", "INFO", msg) }

// tailLog liefert die letzten n Zeilen, optional nur für ein Profil.
func tailLog(id string, n int) []string {
	logMu.Lock()
	defer logMu.Unlock()
	f, err := os.Open(logPath())
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	needle := "[" + id + "] "
	for sc.Scan() {
		l := sc.Text()
		if id == "" || strings.Contains(l, needle) {
			lines = append(lines, l)
			if len(lines) > n*4 {
				lines = lines[len(lines)-n:]
			}
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}
