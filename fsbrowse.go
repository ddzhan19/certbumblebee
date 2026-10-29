package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type fsEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type fsListing struct {
	Path    string    `json:"path"`
	Parent  string    `json:"parent"`
	Root    bool      `json:"root"`
	Entries []fsEntry `json:"entries"`
}

// listDir listet die Unterordner (für die Ordnerauswahl). Leerer Pfad = Laufwerke (Windows) bzw. „/“.
func listDir(p string) (*fsListing, error) {
	win := plat.IsWindows()
	if strings.TrimSpace(p) == "" {
		if win {
			l := &fsListing{Root: true, Entries: []fsEntry{}}
			for _, d := range plat.Drives() {
				l.Entries = append(l.Entries, fsEntry{Name: d, Path: d})
			}
			return l, nil
		}
		p = "/"
	}
	clean, err := validatePath(p, win, "Ordner")
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(clean)
	if err != nil {
		return nil, fmt.Errorf("Der Ordner „%s“ kann nicht geöffnet werden: %v", clean, simplifyOSError(err))
	}
	l := &fsListing{Path: clean, Entries: []fsEntry{}}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		l.Entries = append(l.Entries, fsEntry{Name: e.Name(), Path: filepath.Join(clean, e.Name())})
	}
	sort.Slice(l.Entries, func(i, j int) bool { return strings.ToLower(l.Entries[i].Name) < strings.ToLower(l.Entries[j].Name) })
	if len(l.Entries) > 1000 {
		l.Entries = l.Entries[:1000]
	}
	vol := filepath.VolumeName(clean)
	switch {
	case win && vol != "" && strings.TrimRight(clean, `\`) == vol:
		l.Parent = "" // Laufwerks- oder Freigabe-Stamm: zurück zur Laufwerksliste
		l.Root = false
	case !win && clean == "/":
		l.Parent = ""
	default:
		l.Parent = filepath.Dir(clean)
	}
	return l, nil
}

func simplifyOSError(err error) string {
	var pe *os.PathError
	if e, ok := err.(*os.PathError); ok {
		pe = e
		return pe.Err.Error()
	}
	return err.Error()
}

// testWrite prüft, ob in den Ordner geschrieben werden kann (legt ihn bei Bedarf kurz an).
func testWrite(dir string) (string, error) {
	win := plat.IsWindows()
	clean, err := validatePath(dir, win, "Ordner")
	if err != nil {
		return "", err
	}
	created := ""
	if _, err := os.Stat(clean); err != nil {
		// ersten fehlenden Ordner der Kette merken, um ihn danach wieder zu entfernen
		cur := clean
		for {
			parent := filepath.Dir(cur)
			if _, perr := os.Stat(parent); perr == nil || parent == cur {
				created = cur
				break
			}
			cur = parent
		}
		if err := os.MkdirAll(clean, 0o755); err != nil {
			return "", fmt.Errorf("Der Ordner existiert nicht und lässt sich nicht anlegen: %v", simplifyOSError(err))
		}
	}
	f := filepath.Join(clean, ".certbumblebee-test-"+randomHex(4))
	if err := os.WriteFile(f, []byte("test"), 0o600); err != nil {
		if created != "" {
			_ = os.RemoveAll(created)
		}
		return "", fmt.Errorf("In diesen Ordner kann nicht geschrieben werden: %v", simplifyOSError(err))
	}
	_ = os.Remove(f)
	if created != "" {
		_ = os.RemoveAll(created)
		return "Der Ordner existiert noch nicht, lässt sich aber anlegen und beschreiben. Das Programm legt ihn beim Ausstellen an.", nil
	}
	return "Schreibzugriff ist möglich (mit dem Konto, unter dem dieses Programm gerade läuft).", nil
}
