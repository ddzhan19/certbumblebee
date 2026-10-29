//go:build windows

package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Ein kleines Gerüst aus echten Windows-Steuerelementen (Fenster, Schaltflächen, Listen, Eingabefelder).
// Alles läuft auf einem Thread: Nur der Oberflächen-Thread darf Steuerelemente ändern. Andere Threads
// übergeben ihre Arbeit mit uiPost.

const (
	uiClass   = "CertbumblebeeFenster"
	appIconID = 1 // Kennung der Symbolgruppe (tools/mkresource.py)
	wmUIPost  = wmApp + 1

	idOK     = 1
	idCancel = 2
)

// Verankerung eines Steuerelements beim Vergrößern des Fensters
const (
	anchorL = 1 << iota
	anchorT
	anchorR
	anchorB
)

// Bausteine für Rückruf-Funktionen
type (
	cmdFunc    func(code int)
	notifyFunc func(code uint32, nm unsafe.Pointer)
)

type ctl struct {
	w      *wnd
	hwnd   windows.HWND
	kind   string // label edit memo button check radio combo list progress line status
	id     int
	page   int
	x, y   int // Entwurfskoordinaten bei 96 dpi
	cx, cy int
	anchor uint8
	white  bool   // weißer Grund (Kopfzeile)
	color  uint32 // Textfarbe (BGR)
	colSet bool
	widths []int // Spaltenbreiten (Entwurf) bei Listen
	font   int   // 0 normal, 1 fett, 2 Titel
	shown  bool
}

type wnd struct {
	hwnd       windows.HWND
	owner      *wnd
	dpi        int
	cw, ch     int // Entwurfsgröße des Inhaltsbereichs
	curW, curH int // aktuelle Größe in Entwurfseinheiten
	minW, minH int
	ctls       []*ctl
	nextID     int
	cmd        map[int]cmdFunc
	notify     map[int]notifyFunc
	at         int // Seite, der neu angelegte Steuerelemente zugeordnet werden (0 = immer sichtbar)
	page       int // aktuell sichtbare Seite
	defID      int
	done       bool
	isMain     bool
	resizable  bool
	hasMenu    bool
	style      uint32
	exStyle    uint32
	onClose    func() bool
	onTimer    func(id uintptr)
	onKey      func(vk int) bool
	bands      []rect // weiße Streifen in Entwurfseinheiten
}

var (
	wins     = map[windows.HWND]*wnd{}
	creating *wnd
	msgWnd   windows.HWND
	uiThread uint32

	uiMu    sync.Mutex
	uiQueue []func()

	fontMu sync.Mutex
	fontBy = map[int][3]uintptr{}

	classOnce sync.Once
)

// ---------- Start ----------

// uiInit bereitet den Oberflächen-Thread vor. Muss auf dem Thread laufen, der später die Nachrichten abholt.
func uiInit() {
	runtime.LockOSThread()
	uiThread = windows.GetCurrentThreadId()
	_, _, _ = pCoInitializeEx.Call(0, coinitApartment)
	icc := initCommonControlsEx{Size: uint32(unsafe.Sizeof(initCommonControlsEx{})), ICC: iccListView | iccBar | iccProgress | iccStandard | iccTabs}
	_, _, _ = pInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))
	classOnce.Do(registerClass)
	h, _, _ := pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(u16(uiClass))), 0, 0, 0, 0, 0, 0, hwndMessage, 0, uintptr(hInstance()), 0)
	msgWnd = windows.HWND(h)
}

func registerClass() {
	icon := loadAppIcon(smCxIcon, smCyIcon)
	small := loadAppIcon(smCxSmIcon, smCySmIcon)
	cur, _, _ := pLoadCursor.Call(0, idcArrow)
	wc := wndClassEx{
		Size:       uint32(unsafe.Sizeof(wndClassEx{})),
		WndProc:    windows.NewCallback(wndProc),
		Instance:   hInstance(),
		Icon:       icon,
		IconSm:     small,
		Cursor:     windows.Handle(cur),
		Background: windows.Handle(colorBtnFace + 1),
		ClassName:  u16(uiClass),
	}
	_, _, _ = pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))
}

func loadAppIcon(cxMetric, cyMetric uintptr) windows.Handle {
	cx, _, _ := pGetSystemMetrics.Call(cxMetric)
	cy, _, _ := pGetSystemMetrics.Call(cyMetric)
	h, _, _ := pLoadImage.Call(uintptr(hInstance()), appIconID, imageIcon, cx, cy, lrShared)
	return windows.Handle(h)
}

// uiPost führt fn später auf dem Oberflächen-Thread aus. Darf von jedem Thread aufgerufen werden.
func uiPost(fn func()) {
	uiMu.Lock()
	uiQueue = append(uiQueue, fn)
	uiMu.Unlock()
	if msgWnd != 0 {
		postMsg(msgWnd, wmUIPost, 0, 0)
	}
}

func drainUI() {
	for {
		uiMu.Lock()
		if len(uiQueue) == 0 {
			uiMu.Unlock()
			return
		}
		fn := uiQueue[0]
		uiQueue = uiQueue[1:]
		uiMu.Unlock()
		safely("Hintergrundergebnis", fn)
	}
}

// safely fängt Abstürze in Rückrufen ab, damit ein Fehler nicht das ganze Programm beendet.
func safely(what string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			appLogGlobal(fmt.Sprintf("Oberfläche: Fehler bei „%s“ abgefangen: %v\n%s", what, r, debug.Stack()))
		}
	}()
	fn()
}

// ---------- Schriften ----------

func fontsFor(dpi int) [3]uintptr {
	fontMu.Lock()
	defer fontMu.Unlock()
	if f, ok := fontBy[dpi]; ok {
		return f
	}
	mk := func(pt float64, weight int) uintptr {
		h := -int(pt*float64(dpi)/72 + 0.5)
		r, _, _ := pCreateFont.Call(uintptr(h), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(u16("Segoe UI"))))
		return r
	}
	f := [3]uintptr{mk(9, fwNormal), mk(9, fwBold), mk(12, fwSemiBold)}
	fontBy[dpi] = f
	return f
}

// ---------- Fensterprozedur ----------

func ptrOf(v uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&v)) }

func wndProc(h, m, wp, lp uintptr) (ret uintptr) {
	defer func() {
		if r := recover(); r != nil {
			appLogGlobal(fmt.Sprintf("Oberfläche: Fehler abgefangen (Nachricht 0x%X): %v\n%s", m, r, debug.Stack()))
			ret = 0
		}
	}()
	hw := windows.HWND(h)
	if uint32(m) == wmUIPost {
		drainUI()
		return 0
	}
	w := wins[hw]
	if w == nil {
		if uint32(m) == wmNCCreate && creating != nil {
			creating.hwnd = hw
			wins[hw] = creating
			w = creating
		} else {
			r, _, _ := pDefWindowProc.Call(h, m, wp, lp)
			return r
		}
	}
	switch uint32(m) {
	case wmCommand:
		if f := w.cmd[loword(wp)]; f != nil {
			safely("Schaltfläche", func() { f(hiword(wp)) })
		}
		return 0
	case wmNotify:
		nm := (*nmhdr)(ptrOf(lp))
		if f := w.notify[int(nm.IDFrom)]; f != nil {
			p := ptrOf(lp)
			safely("Meldung", func() { f(nm.Code, p) })
		}
		return 0
	case wmTimer:
		if w.onTimer != nil {
			safely("Zeitgeber", func() { w.onTimer(wp) })
		}
		return 0
	case wmClose:
		w.requestClose()
		return 0
	case wmDestroy:
		delete(wins, hw)
		if w.isMain {
			_, _, _ = pPostQuitMessage.Call(0)
		}
		return 0
	case wmSize:
		if w.resizable && w.cw > 0 {
			r := getRect(hw, true)
			w.curW = int(r.Right) * 96 / w.dpi
			w.curH = int(r.Bottom) * 96 / w.dpi
			w.relayout()
		}
		return 0
	case wmGetMinMaxInfo:
		if w.minW > 0 {
			mi := (*minMaxInfo)(ptrOf(lp))
			rc := rect{0, 0, int32(w.px(w.minW)), int32(w.px(w.minH))}
			w.adjust(&rc)
			mi.MinTrackSize = point{rc.Right - rc.Left, rc.Bottom - rc.Top}
		}
		return 0
	case wmDMGetDefID:
		if w.defID != 0 {
			return uintptr(w.defID) | dcHasDefID<<16
		}
		return 0
	case wmDpiChanged:
		nr := (*rect)(ptrOf(lp))
		_, _, _ = pSetWindowPos.Call(h, 0, uintptr(nr.Left), uintptr(nr.Top), uintptr(nr.Right-nr.Left), uintptr(nr.Bottom-nr.Top), swpNoZOrder|swpNoActivate)
		w.setDPI(hiword(wp))
		return 0
	case wmEraseBkgnd:
		r, _, _ := pDefWindowProc.Call(h, m, wp, lp)
		wb, _, _ := pGetStockObject.Call(whiteBrush)
		for _, b := range w.bands {
			rc := rect{int32(w.px(int(b.Left))), int32(w.px(int(b.Top))), int32(w.px(int(b.Right))), int32(w.px(int(b.Bottom)))}
			_, _, _ = pFillRect.Call(wp, uintptr(unsafe.Pointer(&rc)), wb)
		}
		return r
	case wmCtlColorStat, wmCtlColorEdit:
		if r, ok := w.paintColors(wp, lp); ok {
			return r
		}
	}
	r, _, _ := pDefWindowProc.Call(h, m, wp, lp)
	return r
}

func (w *wnd) byHwnd(h windows.HWND) *ctl {
	for _, c := range w.ctls {
		if c.hwnd == h {
			return c
		}
	}
	return nil
}

// paintColors liefert Pinsel und Farben für Beschriftungen mit besonderem Grund oder besonderer Textfarbe.
func (w *wnd) paintColors(hdc, ctlH uintptr) (uintptr, bool) {
	c := w.byHwnd(windows.HWND(ctlH))
	if c == nil {
		return 0, false
	}
	switch {
	case c.white:
		_, _, _ = pSetBkColor.Call(hdc, 0x00FFFFFF)
		text := uintptr(0x00000000)
		if c.colSet {
			text = uintptr(c.color)
		}
		_, _, _ = pSetTextColor.Call(hdc, text)
		b, _, _ := pGetStockObject.Call(whiteBrush)
		return b, true
	case c.kind == "memo" || c.kind == "edit":
		// schreibgeschützte Felder wie normale Felder (weiß) zeichnen
		col, _, _ := pGetSysColor.Call(colorWindow)
		_, _, _ = pSetBkColor.Call(hdc, col)
		b, _, _ := pGetSysColorBrush.Call(colorWindow)
		return b, true
	case c.colSet:
		col, _, _ := pGetSysColor.Call(colorBtnFace)
		_, _, _ = pSetBkColor.Call(hdc, col)
		_, _, _ = pSetTextColor.Call(hdc, uintptr(c.color))
		b, _, _ := pGetSysColorBrush.Call(colorBtnFace)
		return b, true
	}
	return 0, false
}

// ---------- Fenster anlegen ----------

func (w *wnd) px(v int) int { return (v*w.dpi + 48) / 96 }

func (w *wnd) adjust(rc *rect) {
	menu := uintptr(0)
	if w.hasMenu {
		menu = 1
	}
	if pAdjustWindowRectDpi.Find() == nil {
		_, _, _ = pAdjustWindowRectDpi.Call(uintptr(unsafe.Pointer(rc)), uintptr(w.style), menu, uintptr(w.exStyle), uintptr(w.dpi))
		return
	}
	_, _, _ = pAdjustWindowRect.Call(uintptr(unsafe.Pointer(rc)), uintptr(w.style), menu, uintptr(w.exStyle))
}

// newWindow legt ein Fenster mit Inhaltsbereich cw × ch (Entwurfseinheiten bei 96 dpi) an.
func newWindow(owner *wnd, title string, cw, ch int, main bool) *wnd {
	w := &wnd{owner: owner, cw: cw, ch: ch, curW: cw, curH: ch, cmd: map[int]cmdFunc{}, notify: map[int]notifyFunc{}, nextID: 100, isMain: main}
	w.dpi = systemDPI()
	if owner != nil {
		w.dpi = owner.dpi
	}
	if main {
		w.style = wsOverlapped | wsCaption | wsSysMenu | wsThickFrame | wsMinimizeBox | wsMaximizeBox | wsClipChildren
		w.exStyle = wsExControlParent | wsExAppWindow
	} else {
		w.style = wsPopup | wsCaption | wsSysMenu | wsClipChildren
		w.exStyle = wsExDlgModalFrame | wsExControlParent
	}
	rc := rect{0, 0, int32(w.px(cw)), int32(w.px(ch))}
	w.adjust(&rc)
	creating = w
	h, _, _ := pCreateWindowEx.Call(uintptr(w.exStyle), uintptr(unsafe.Pointer(u16(uiClass))), uintptr(unsafe.Pointer(u16(title))),
		uintptr(w.style), cwUseDefault, cwUseDefault, uintptr(rc.Right-rc.Left), uintptr(rc.Bottom-rc.Top),
		ownerHwnd(owner), 0, uintptr(hInstance()), 0)
	creating = nil
	if h == 0 {
		return nil
	}
	w.hwnd = windows.HWND(h)
	if d := windowDPI(w.hwnd); d != w.dpi {
		w.dpi = d
		rc = rect{0, 0, int32(w.px(cw)), int32(w.px(ch))}
		w.adjust(&rc)
		_, _, _ = pSetWindowPos.Call(h, 0, 0, 0, uintptr(rc.Right-rc.Left), uintptr(rc.Bottom-rc.Top), swpNoMove|swpNoZOrder|swpNoActivate)
	}
	return w
}

func ownerHwnd(o *wnd) uintptr {
	if o == nil {
		return 0
	}
	return uintptr(o.hwnd)
}

// center setzt das Fenster in die Mitte des Besitzers oder des Bildschirms.
func (w *wnd) center() {
	wr := getRect(w.hwnd, false)
	ww, wh := int(wr.Right-wr.Left), int(wr.Bottom-wr.Top)
	area := screenWork()
	var x, y int
	if w.owner != nil {
		or := getRect(w.owner.hwnd, false)
		x = int(or.Left) + (int(or.Right-or.Left)-ww)/2
		y = int(or.Top) + (int(or.Bottom-or.Top)-wh)/2
	} else {
		x = int(area.Left) + (int(area.Right-area.Left)-ww)/2
		y = int(area.Top) + (int(area.Bottom-area.Top)-wh)/2
	}
	if x+ww > int(area.Right) {
		x = int(area.Right) - ww
	}
	if y+wh > int(area.Bottom) {
		y = int(area.Bottom) - wh
	}
	if x < int(area.Left) {
		x = int(area.Left)
	}
	if y < int(area.Top) {
		y = int(area.Top)
	}
	_, _, _ = pSetWindowPos.Call(uintptr(w.hwnd), 0, uintptr(x), uintptr(y), 0, 0, swpNoSize|swpNoZOrder|swpNoActivate)
}

func (w *wnd) setTitle(s string) { setText(w.hwnd, s) }

func (w *wnd) requestClose() {
	if w.onClose != nil && !w.onClose() {
		return
	}
	if w.isMain {
		_, _, _ = pDestroyWindow.Call(uintptr(w.hwnd))
		return
	}
	w.done = true
}

// ---------- Nachrichtenschleife ----------

func runLoop(until func() bool) {
	var m msgT
	for !until() {
		r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			if int32(r) == 0 {
				_, _, _ = pPostQuitMessage.Call(m.WParam)
			}
			return
		}
		if preTranslate(&m) {
			continue
		}
		_, _, _ = pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		_, _, _ = pDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func preTranslate(m *msgT) bool {
	root, _, _ := pGetAncestor.Call(uintptr(m.Hwnd), gaRoot)
	w := wins[windows.HWND(root)]
	if w == nil {
		return false
	}
	if m.Message == wmKeyDown {
		if m.WParam == 'A' && keyDown(vkControl) && className(m.Hwnd) == "Edit" {
			sendMsg(m.Hwnd, emSetSel, 0, ^uintptr(0))
			return true
		}
		if w.onKey != nil && w.onKey(int(m.WParam)) {
			return true
		}
	}
	r, _, _ := pIsDialogMessage.Call(root, uintptr(unsafe.Pointer(m)))
	return r != 0
}

func keyDown(vk int) bool {
	r, _, _ := pGetKeyState.Call(uintptr(vk))
	return r&0x8000 != 0
}

// showModal zeigt das Fenster, sperrt den Besitzer und kehrt zurück, wenn das Fenster geschlossen wurde.
func (w *wnd) showModal() {
	if w.owner != nil {
		_, _, _ = pEnableWindow.Call(uintptr(w.owner.hwnd), 0)
	}
	w.center()
	w.setPage(w.page)
	_, _, _ = pShowWindow.Call(uintptr(w.hwnd), swShow)
	_, _, _ = pSetForegroundWindow.Call(uintptr(w.hwnd))
	runLoop(func() bool { return w.done })
	if w.owner != nil {
		_, _, _ = pEnableWindow.Call(uintptr(w.owner.hwnd), 1)
	}
	_, _, _ = pDestroyWindow.Call(uintptr(w.hwnd))
	if w.owner != nil {
		_, _, _ = pSetForegroundWindow.Call(uintptr(w.owner.hwnd))
	}
}

func (w *wnd) close() { w.done = true }

// ---------- Layout und Seiten ----------

func (c *ctl) rectPx() (x, y, cx, cy int) {
	w := c.w
	lx, ly, lw, lh := c.x, c.y, c.cx, c.cy
	dw, dh := w.curW-w.cw, w.curH-w.ch
	if c.anchor&anchorR != 0 {
		if c.anchor&anchorL != 0 {
			lw += dw
		} else {
			lx += dw
		}
	}
	if c.anchor&anchorB != 0 {
		if c.anchor&anchorT != 0 {
			lh += dh
		} else {
			ly += dh
		}
	}
	if lw < 1 {
		lw = 1
	}
	if lh < 1 {
		lh = 1
	}
	return w.px(lx), w.px(ly), w.px(lw), w.px(lh)
}

func (w *wnd) relayout() {
	for _, c := range w.ctls {
		x, y, cx, cy := c.rectPx()
		_, _, _ = pMoveWindow.Call(uintptr(c.hwnd), uintptr(x), uintptr(y), uintptr(cx), uintptr(cy), 1)
	}
}

func (w *wnd) setDPI(d int) {
	if d == w.dpi || d < 96 {
		return
	}
	w.dpi = d
	f := fontsFor(d)
	for _, c := range w.ctls {
		sendMsg(c.hwnd, wmSetFont, f[c.font], 1)
		if c.kind == "list" {
			for i, wd := range c.widths {
				sendMsg(c.hwnd, lvmSetColWidth, uintptr(i), uintptr(w.px(wd)))
			}
		}
	}
	w.relayout()
}

// setPage zeigt die Steuerelemente der Seite n (und die ohne Seite).
func (w *wnd) setPage(n int) {
	w.page = n
	for _, c := range w.ctls {
		c.apply()
	}
}

func (c *ctl) apply() {
	vis := (c.page == 0 || c.page == c.w.page) && c.shown
	cmd := uintptr(swHide)
	if vis {
		cmd = swShow
	}
	_, _, _ = pShowWindow.Call(uintptr(c.hwnd), cmd)
}

// ---------- Steuerelemente anlegen ----------

func (w *wnd) add(kind, class, text string, style, ex uint32, x, y, cx, cy int) *ctl {
	c := &ctl{w: w, kind: kind, id: w.nextID, page: w.at, x: x, y: y, cx: cx, cy: cy, shown: true}
	w.nextID++
	px, py, pcx, pcy := c.rectPx()
	st := style | wsChild | wsClipSiblings
	if c.page == 0 || c.page == w.page {
		st |= wsVisible
	}
	h, _, _ := pCreateWindowEx.Call(uintptr(ex), uintptr(unsafe.Pointer(u16(class))), uintptr(unsafe.Pointer(u16(text))), uintptr(st),
		uintptr(px), uintptr(py), uintptr(pcx), uintptr(pcy), uintptr(w.hwnd), uintptr(c.id), uintptr(hInstance()), 0)
	c.hwnd = windows.HWND(h)
	sendMsg(c.hwnd, wmSetFont, fontsFor(w.dpi)[0], 1)
	w.ctls = append(w.ctls, c)
	return c
}

func (w *wnd) label(x, y, cx, cy int, text string) *ctl {
	return w.add("label", "STATIC", text, ssLeft|ssNoPrefix, 0, x, y, cx, cy)
}

func (w *wnd) edit(x, y, cx, cy int, text string) *ctl {
	c := w.add("edit", "EDIT", text, esAutoHScroll|wsTabStop, wsExClientEdge, x, y, cx, cy)
	sendMsg(c.hwnd, emLimitText, 4096, 0)
	return c
}

func (w *wnd) password(x, y, cx, cy int) *ctl {
	c := w.add("edit", "EDIT", "", esAutoHScroll|esPassword|wsTabStop, wsExClientEdge, x, y, cx, cy)
	sendMsg(c.hwnd, emLimitText, 200, 0)
	return c
}

func (w *wnd) memo(x, y, cx, cy int, readOnly bool) *ctl {
	st := uint32(esMultiline | esAutoVScroll | wsVScroll | wsTabStop)
	if readOnly {
		st |= esReadOnly
	} else {
		st |= esWantReturn
	}
	c := w.add("memo", "EDIT", "", st, wsExClientEdge, x, y, cx, cy)
	sendMsg(c.hwnd, emLimitText, 2_000_000, 0)
	return c
}

func (w *wnd) button(x, y, cx, cy int, text string, onClick func()) *ctl {
	c := w.add("button", "BUTTON", text, bsPushButton|wsTabStop, 0, x, y, cx, cy)
	if onClick != nil {
		w.cmd[c.id] = func(code int) {
			if code == bnClicked {
				onClick()
			}
		}
	}
	return c
}

func (w *wnd) check(x, y, cx, cy int, text string, onChange func()) *ctl {
	c := w.add("check", "BUTTON", text, bsAutoCheckBox|wsTabStop, 0, x, y, cx, cy)
	if onChange != nil {
		w.cmd[c.id] = func(code int) {
			if code == bnClicked {
				onChange()
			}
		}
	}
	return c
}

// radio legt einen Auswahlknopf an. first=true beginnt eine neue Gruppe.
func (w *wnd) radio(x, y, cx, cy int, text string, first bool, onChange func()) *ctl {
	st := uint32(bsAutoRadio)
	if first {
		st |= wsGroup | wsTabStop
	}
	c := w.add("radio", "BUTTON", text, st, 0, x, y, cx, cy)
	if onChange != nil {
		w.cmd[c.id] = func(code int) {
			if code == bnClicked {
				onChange()
			}
		}
	}
	return c
}

func (w *wnd) combo(x, y, cx int, items []string, onChange func()) *ctl {
	c := w.add("combo", "COMBOBOX", "", cbsDropDownList|wsVScroll|wsTabStop, 0, x, y, cx, 200)
	for _, it := range items {
		sendStr(c.hwnd, cbAddString, 0, it)
	}
	sendMsg(c.hwnd, cbSetCurSel, 0, 0)
	if onChange != nil {
		w.cmd[c.id] = func(code int) {
			if code == cbnSelChange {
				onChange()
			}
		}
	}
	return c
}

// line zeichnet eine feine waagerechte Trennlinie.
func (w *wnd) line(x, y, cx int) *ctl {
	return w.add("line", "STATIC", "", ssEtchedHorz, 0, x, y, cx, 2)
}

// band zeichnet einen weißen Streifen (Kopfzeile).
// band legt einen weißen Streifen (Kopfzeile) an. Er wird beim Hintergrundzeichnen des Fensters
// gemalt und ist kein eigenes Steuerelement, damit die Beschriftungen darauf immer sichtbar bleiben.
func (w *wnd) band(x, y, cx, cy int) {
	w.bands = append(w.bands, rect{int32(x), int32(y), int32(x + cx), int32(y + cy)})
}

func (w *wnd) progressBar(x, y, cx, cy int) *ctl {
	return w.add("progress", "msctls_progress32", "", pbsMarquee, 0, x, y, cx, cy)
}

func (w *wnd) statusBar() *ctl {
	c := w.add("status", "msctls_statusbar32", "", sbarsGrip, 0, 0, w.ch-22, w.cw, 22)
	c.anchor = anchorL | anchorR | anchorB
	return c
}

// list legt eine Liste in Berichtsansicht an.
func (w *wnd) list(x, y, cx, cy int, header bool, cols []string, widths []int) *ctl {
	st := uint32(lvsReport | lvsSingleSel | lvsShowSelAlways | wsTabStop)
	if !header {
		st |= lvsNoColumnHdr
	} else {
		st |= lvsNoSortHeader
	}
	c := w.add("list", "SysListView32", "", st, wsExClientEdge, x, y, cx, cy)
	sendMsg(c.hwnd, lvmSetExStyle, lvsExFullRowSel|lvsExDoubleBuf|lvsExLabelTip, lvsExFullRowSel|lvsExDoubleBuf|lvsExLabelTip)
	_, _, _ = pSetWindowTheme.Call(uintptr(c.hwnd), uintptr(unsafe.Pointer(u16("Explorer"))), 0)
	for i, t := range cols {
		wd := 100
		if i < len(widths) {
			wd = widths[i]
		}
		c.addColumn(t, wd)
	}
	return c
}

// ---------- Eigenschaften der Steuerelemente ----------

func (c *ctl) setText(s string) {
	if c.kind == "memo" {
		s = toCRLF(s)
	}
	setText(c.hwnd, s)
}

func (c *ctl) text() string {
	s := getText(c.hwnd)
	if c.kind == "memo" {
		s = fromCRLF(s)
	}
	return s
}

func (c *ctl) trimmed() string { return strings.TrimSpace(c.text()) }

// startGroup beginnt hier eine neue Gruppe für die Pfeiltasten-Bedienung von Auswahlknöpfen.
func (c *ctl) startGroup() {
	st, _, _ := pGetWindowLongPtr.Call(uintptr(c.hwnd), gwlStyle)
	_, _, _ = pSetWindowLongPtr.Call(uintptr(c.hwnd), gwlStyle, st|wsGroup)
}

// cue zeigt einen grauen Hinweistext im leeren Eingabefeld.
func (c *ctl) cue(s string) { sendStr(c.hwnd, emSetCueBanner, 0, s) }

func (c *ctl) setChecked(v bool) {
	n := uintptr(0)
	if v {
		n = 1
	}
	sendMsg(c.hwnd, bmSetCheck, n, 0)
}

func (c *ctl) checked() bool { return sendMsg(c.hwnd, bmGetCheck, 0, 0) == 1 }

func (c *ctl) enable(v bool) {
	n := uintptr(0)
	if v {
		n = 1
	}
	_, _, _ = pEnableWindow.Call(uintptr(c.hwnd), n)
}

// show blendet das Element ein oder aus (zusätzlich zur Seitenwahl).
func (c *ctl) show(v bool) {
	c.shown = v
	c.apply()
}

func (c *ctl) focus() { _, _, _ = pSetFocus.Call(uintptr(c.hwnd)) }

func (c *ctl) setFont(kind int) {
	c.font = kind
	sendMsg(c.hwnd, wmSetFont, fontsFor(c.w.dpi)[kind], 1)
}

func (c *ctl) setColor(bgr uint32) { c.color, c.colSet = bgr, true }

func (c *ctl) onClick(f func()) {
	c.w.cmd[c.id] = func(code int) {
		if code == bnClicked {
			f()
		}
	}
}

// ComboBox
func (c *ctl) comboIndex() int { return int(int32(sendMsg(c.hwnd, cbGetCurSel, 0, 0))) }
func (c *ctl) setComboIndex(i int) {
	sendMsg(c.hwnd, cbSetCurSel, uintptr(i), 0)
}

// Eingabefeld
func (c *ctl) setReadOnly(v bool) {
	n := uintptr(0)
	if v {
		n = 1
	}
	sendMsg(c.hwnd, emSetReadOnly, n, 0)
}

// showPassword zeigt oder verbirgt den Inhalt eines Kennwortfeldes.
func (c *ctl) showPassword(v bool) {
	ch := uintptr('•')
	if v {
		ch = 0
	}
	sendMsg(c.hwnd, emSetPwdChar, ch, 0)
	_, _, _ = pInvalidateRect.Call(uintptr(c.hwnd), 0, 1)
}

// Fortschrittsbalken
func (c *ctl) marquee(on bool) {
	n := uintptr(0)
	if on {
		n = 1
	}
	sendMsg(c.hwnd, pbmSetMarq, n, 30)
}

// Statusleiste
func (c *ctl) setStatus(s string) { sendStr(c.hwnd, sbSetTextW, 0, s) }

// ---------- Listen ----------

func (c *ctl) addColumn(title string, width int) {
	col := lvColumn{Mask: lvcfFmt | lvcfWidth | lvcfText | lvcfSubItem, Fmt: lvcfmtLeft, Cx: int32(c.w.px(width)), Text: u16(title), SubItem: int32(len(c.widths))}
	sendPtr(c.hwnd, lvmInsertColumn, uintptr(len(c.widths)), unsafe.Pointer(&col))
	c.widths = append(c.widths, width)
}

func (c *ctl) clearRows() { sendMsg(c.hwnd, lvmDeleteAll, 0, 0) }

func (c *ctl) rowCount() int { return int(sendMsg(c.hwnd, lvmGetItemCount, 0, 0)) }

func (c *ctl) addRow(cells ...string) int {
	idx := c.rowCount()
	first := ""
	if len(cells) > 0 {
		first = cells[0]
	}
	it := lvItem{Mask: lvifText, Item: int32(idx), Text: u16(first)}
	sendPtr(c.hwnd, lvmInsertItem, 0, unsafe.Pointer(&it))
	for i := 1; i < len(cells); i++ {
		c.setCell(idx, i, cells[i])
	}
	return idx
}

func (c *ctl) setCell(row, col int, s string) {
	it := lvItem{SubItem: int32(col), Text: u16(s)}
	sendPtr(c.hwnd, lvmSetItemText, uintptr(row), unsafe.Pointer(&it))
}

func (c *ctl) cell(row, col int) string {
	buf := make([]uint16, 2048)
	it := lvItem{SubItem: int32(col), Text: &buf[0], CchTextMax: int32(len(buf))}
	n := sendPtr(c.hwnd, lvmGetItemText, uintptr(row), unsafe.Pointer(&it))
	return windows.UTF16ToString(buf[:n])
}

func (c *ctl) selectedRow() int {
	return int(int32(sendMsg(c.hwnd, lvmGetNextItem, ^uintptr(0), lvniSelected)))
}

func (c *ctl) selectRow(row int) {
	it := lvItem{State: lvisSelected | lvisFocused, StateMask: lvisSelected | lvisFocused}
	sendPtr(c.hwnd, lvmSetItemState, uintptr(row), unsafe.Pointer(&it))
	sendMsg(c.hwnd, lvmEnsureVisible, uintptr(row), 0)
}

// onSelect meldet, wenn sich die Auswahl ändert. onActivate bei Doppelklick oder Eingabetaste.
func (c *ctl) onSelect(f func()) {
	prev := c.w.notify[c.id]
	c.w.notify[c.id] = func(code uint32, nm unsafe.Pointer) {
		if code == lvnItemChanged {
			n := (*nmListView)(nm)
			if n.Changed&lvifState != 0 && (n.NewState^n.OldState)&lvisSelected != 0 {
				f()
			}
		}
		if prev != nil {
			prev(code, nm)
		}
	}
}

func (c *ctl) onActivate(f func()) {
	prev := c.w.notify[c.id]
	c.w.notify[c.id] = func(code uint32, nm unsafe.Pointer) {
		if code == lvnItemActivate || code == nmDblClk {
			f()
		}
		if prev != nil {
			prev(code, nm)
		}
	}
}

// ---------- Hilfsfenster ----------

func (w *wnd) timer(id uintptr, ms int) {
	_, _, _ = pSetTimer.Call(uintptr(w.hwnd), id, uintptr(ms), 0)
}

func (w *wnd) killTimer(id uintptr) { _, _, _ = pKillTimer.Call(uintptr(w.hwnd), id) }

func hwndOf(w *wnd) windows.HWND {
	if w == nil {
		return 0
	}
	return w.hwnd
}

func msgBox(owner *wnd, text, title string, flags uint32) int {
	r, _ := windows.MessageBox(hwndOf(owner), u16(text), u16(title), flags|windows.MB_SETFOREGROUND)
	return int(r)
}

func infoBox(owner *wnd, text string)  { msgBox(owner, text, appName, mbIconInfo) }
func errorBox(owner *wnd, text string) { msgBox(owner, text, appName, mbIconError) }
func warnBox(owner *wnd, text string)  { msgBox(owner, text, appName, mbIconWarn) }

// askBox stellt eine Ja/Nein-Frage; die Voreinstellung ist „Nein“.
func askBox(owner *wnd, text string) bool {
	return msgBox(owner, text, appName, mbYesNo|mbIconQuest|mbDefButton2) == idYes
}

func utf16Multi(parts ...string) []uint16 {
	var out []uint16
	for _, p := range parts {
		u, _ := windows.UTF16FromString(p)
		out = append(out, u...)
	}
	return append(out, 0)
}

// openFiles zeigt „Datei öffnen“. filter: Paare aus Anzeigename und Muster, z. B. "Zertifikate", "*.crt;*.cer".
func openFiles(owner *wnd, title string, multi bool, filter ...string) []string {
	buf := make([]uint16, 32768)
	ofn := openFileName{
		StructSize: uint32(unsafe.Sizeof(openFileName{})), Owner: hwndOf(owner), Filter: &utf16Multi(filter...)[0],
		File: &buf[0], MaxFile: uint32(len(buf)), Title: u16(title), Flags: ofnFileMustExist | ofnPathMustExist | ofnExplorer | ofnHideReadOnly | ofnNoChangeDir,
	}
	if multi {
		ofn.Flags |= ofnAllowMulti
	}
	if r, _, _ := pGetOpenFileName.Call(uintptr(unsafe.Pointer(&ofn))); r == 0 {
		return nil
	}
	// Ein Treffer: vollständiger Pfad. Mehrere: Ordner, dann Dateinamen, durch Nullzeichen getrennt.
	var parts []string
	start := 0
	for i := 0; i < len(buf)-1; i++ {
		if buf[i] == 0 {
			if i == start {
				break
			}
			parts = append(parts, windows.UTF16ToString(buf[start:i]))
			start = i + 1
		}
	}
	if len(parts) > 1 {
		dir := parts[0]
		var out []string
		for _, n := range parts[1:] {
			out = append(out, strings.TrimRight(dir, `\`)+`\`+n)
		}
		return out
	}
	return parts
}

// saveFile zeigt „Speichern unter“ und liefert den gewählten Pfad (leer bei Abbruch).
func saveFile(owner *wnd, title, defName, defExt string, filter ...string) string {
	buf := make([]uint16, 4096)
	copy(buf, utf16Multi(defName))
	ofn := openFileName{
		StructSize: uint32(unsafe.Sizeof(openFileName{})), Owner: hwndOf(owner), Filter: &utf16Multi(filter...)[0],
		File: &buf[0], MaxFile: uint32(len(buf)), Title: u16(title), DefExt: u16(defExt),
		Flags: ofnOverwritePromt | ofnPathMustExist | ofnExplorer | ofnHideReadOnly | ofnNoChangeDir,
	}
	if r, _, _ := pGetSaveFileName.Call(uintptr(unsafe.Pointer(&ofn))); r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}

var (
	browseInitial *uint16
	browseCb      = windows.NewCallback(func(h, m, lp, data uintptr) uintptr {
		if uint32(m) == bffmInitialized && browseInitial != nil {
			sendMsg(windows.HWND(h), bffmSetSelectionW, 1, uintptr(unsafe.Pointer(browseInitial)))
		}
		return 0
	})
)

// pickFolder zeigt die Ordnerauswahl; bei Abbruch ist das Ergebnis leer.
func pickFolder(owner *wnd, title, initial string) string {
	name := make([]uint16, 1024)
	browseInitial = u16(initial)
	bi := browseInfo{Owner: hwndOf(owner), DisplayName: &name[0], Title: u16(title), Flags: bifReturnOnlyFSDirs | bifUseNewUI, Callback: browseCb}
	pidl, _, _ := pSHBrowseForFolder.Call(uintptr(unsafe.Pointer(&bi)))
	if pidl == 0 {
		return ""
	}
	defer pCoTaskMemFree.Call(pidl)
	path := make([]uint16, 1024)
	if r, _, _ := pSHGetPathFromIDList.Call(pidl, uintptr(unsafe.Pointer(&path[0]))); r == 0 {
		return ""
	}
	return windows.UTF16ToString(path)
}
