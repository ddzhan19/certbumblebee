package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCF bildet den Teil der Cloudflare-API nach, den das Programm benutzt.
type fakeCF struct {
	t     *testing.T
	srv   *httptest.Server
	token string

	mu          sync.Mutex
	zones       map[string]*fakeZone
	next        int
	reqs        []string
	forbidWrite bool            // Token darf lesen, aber nicht schreiben
	cname       map[string]bool // für diese Namen gibt es einen CNAME
	throttle    int             // die nächsten n Anfragen mit 429 beantworten
	onChange    func(name string, values []string)
}

type fakeZone struct {
	ID, Name string
	NS       []string
	recs     []fakeRec
}

type fakeRec struct{ ID, Type, Name, Content, Comment string }

func newFakeCF(t *testing.T, token string) *fakeCF {
	t.Helper()
	f := &fakeCF{t: t, token: token, zones: map[string]*fakeZone{}, cname: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	cfRetryWait = 5 * time.Millisecond
	t.Cleanup(func() { cfRetryWait = 2 * time.Second })
	t.Setenv("ZA_CLOUDFLARE_API", f.srv.URL)
	return f
}

func (f *fakeCF) addZone(name string) *fakeZone {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	z := &fakeZone{ID: fmt.Sprintf("zone%04d", f.next), Name: name, NS: []string{"ada.ns.cloudflare.test", "bob.ns.cloudflare.test"}}
	f.zones[name] = z
	return z
}

// txt liefert die Werte der TXT-Einträge mit diesem Namen.
func (f *fakeCF) txt(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.txtLocked(name)
}

func (f *fakeCF) txtLocked(name string) []string {
	var out []string
	for _, z := range f.zones {
		for _, r := range z.recs {
			if r.Type == "TXT" && r.Name == name {
				out = append(out, r.Content)
			}
		}
	}
	return out
}

func (f *fakeCF) countRecords() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, z := range f.zones {
		n += len(z.recs)
	}
	return n
}

func (f *fakeCF) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

func cfReply(w http.ResponseWriter, code int, success bool, result any, errs ...cfError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if errs == nil {
		errs = []cfError{}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": success, "errors": errs, "messages": []string{}, "result": result,
		"result_info": map[string]any{"page": 1, "per_page": 50, "count": 0, "total_count": lenOf(result), "total_pages": 1}})
}

func lenOf(v any) int {
	if zs, ok := v.([]map[string]any); ok {
		return len(zs)
	}
	return 0
}

func (f *fakeCF) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.reqs = append(f.reqs, r.Method+" "+r.URL.RequestURI())
	if f.throttle > 0 {
		f.throttle--
		f.mu.Unlock()
		w.Header().Set("Retry-After", "0")
		cfReply(w, 429, false, nil, cfError{971, "Too many requests"})
		return
	}
	f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		cfReply(w, 401, false, nil, cfError{9109, "Invalid access token"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	switch {
	case r.Method == "GET" && path == "zones":
		f.mu.Lock()
		defer f.mu.Unlock()
		name := r.URL.Query().Get("name")
		res := []map[string]any{}
		for _, z := range f.zones {
			if name == "" || name == z.Name {
				res = append(res, map[string]any{"id": z.ID, "name": z.Name, "status": "active", "name_servers": z.NS})
			}
		}
		cfReply(w, 200, true, res)
	case len(parts) >= 3 && parts[0] == "zones" && parts[2] == "dns_records":
		f.records(w, r, parts)
	default:
		cfReply(w, 404, false, nil, cfError{7000, "No route for that URI"})
	}
}

func (f *fakeCF) records(w http.ResponseWriter, r *http.Request, parts []string) {
	f.mu.Lock()
	var z *fakeZone
	for _, c := range f.zones {
		if c.ID == parts[1] {
			z = c
		}
	}
	if z == nil {
		f.mu.Unlock()
		cfReply(w, 404, false, nil, cfError{7003, "Could not route to /zones/x/dns_records, perhaps your object identifier is invalid?"})
		return
	}
	var notify func()
	defer func() {
		f.mu.Unlock()
		if notify != nil {
			notify()
		}
	}()
	changed := func(name string) {
		if f.onChange != nil {
			vals := f.txtLocked(name)
			cb := f.onChange
			notify = func() { cb(name, vals) }
		}
	}
	switch {
	case r.Method == "GET" && len(parts) == 3:
		q := r.URL.Query()
		res := []map[string]any{}
		for _, x := range z.recs {
			if (q.Get("type") == "" || q.Get("type") == x.Type) && (q.Get("name") == "" || q.Get("name") == x.Name) && (q.Get("content") == "" || q.Get("content") == x.Content) {
				res = append(res, map[string]any{"id": x.ID, "type": x.Type, "name": x.Name, "content": x.Content, "comment": x.Comment})
			}
		}
		cfReply(w, 200, true, res)
	case r.Method == "POST" && len(parts) == 3:
		if f.forbidWrite {
			cfReply(w, 403, false, nil, cfError{10000, "Authentication error"})
			return
		}
		var b struct{ Type, Name, Content, Comment string }
		_ = json.NewDecoder(r.Body).Decode(&b)
		if f.cname[b.Name] {
			cfReply(w, 400, false, nil, cfError{81053, "An A, AAAA, or CNAME record with that host already exists."})
			return
		}
		for _, x := range z.recs {
			if x.Type == b.Type && x.Name == b.Name && x.Content == b.Content {
				cfReply(w, 400, false, nil, cfError{81058, "A record with those settings already exists."})
				return
			}
		}
		if !strings.HasSuffix(b.Name, z.Name) {
			cfReply(w, 400, false, nil, cfError{9005, "Content for A record is invalid / name outside zone"})
			return
		}
		f.next++
		rec := fakeRec{ID: fmt.Sprintf("rec%05d", f.next), Type: b.Type, Name: b.Name, Content: b.Content, Comment: b.Comment}
		z.recs = append(z.recs, rec)
		changed(b.Name)
		cfReply(w, 200, true, map[string]any{"id": rec.ID, "type": rec.Type, "name": rec.Name, "content": rec.Content})
	case r.Method == "DELETE" && len(parts) == 4:
		if f.forbidWrite {
			cfReply(w, 403, false, nil, cfError{10000, "Authentication error"})
			return
		}
		for i, x := range z.recs {
			if x.ID == parts[3] {
				z.recs = append(z.recs[:i], z.recs[i+1:]...)
				changed(x.Name)
				cfReply(w, 200, true, map[string]any{"id": x.ID})
				return
			}
		}
		cfReply(w, 404, false, nil, cfError{81044, "Record does not exist."})
	default:
		cfReply(w, 405, false, nil, cfError{7001, "Method not allowed"})
	}
}
