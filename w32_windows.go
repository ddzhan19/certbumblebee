//go:build windows

package main

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Anbindung der Windows-API für die Programmoberfläche. Es wird nur golang.org/x/sys/windows benutzt,
// keine Oberflächenbibliothek.

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	comctl32 = windows.NewLazySystemDLL("comctl32.dll")
	comdlg32 = windows.NewLazySystemDLL("comdlg32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	ole32    = windows.NewLazySystemDLL("ole32.dll")
	uxtheme  = windows.NewLazySystemDLL("uxtheme.dll")

	pRegisterClassEx     = user32.NewProc("RegisterClassExW")
	pCreateWindowEx      = user32.NewProc("CreateWindowExW")
	pDestroyWindow       = user32.NewProc("DestroyWindow")
	pDefWindowProc       = user32.NewProc("DefWindowProcW")
	pShowWindow          = user32.NewProc("ShowWindow")
	pUpdateWindow        = user32.NewProc("UpdateWindow")
	pMoveWindow          = user32.NewProc("MoveWindow")
	pSetWindowPos        = user32.NewProc("SetWindowPos")
	pGetClientRect       = user32.NewProc("GetClientRect")
	pFillRect            = user32.NewProc("FillRect")
	pGetWindowRect       = user32.NewProc("GetWindowRect")
	pSetWindowText       = user32.NewProc("SetWindowTextW")
	pGetWindowText       = user32.NewProc("GetWindowTextW")
	pGetWindowTextLength = user32.NewProc("GetWindowTextLengthW")
	pSendMessage         = user32.NewProc("SendMessageW")
	pPostMessage         = user32.NewProc("PostMessageW")
	pGetMessage          = user32.NewProc("GetMessageW")
	pTranslateMessage    = user32.NewProc("TranslateMessage")
	pDispatchMessage     = user32.NewProc("DispatchMessageW")
	pIsDialogMessage     = user32.NewProc("IsDialogMessageW")
	pPostQuitMessage     = user32.NewProc("PostQuitMessage")
	pEnableWindow        = user32.NewProc("EnableWindow")
	pIsWindowEnabled     = user32.NewProc("IsWindowEnabled")
	pSetFocus            = user32.NewProc("SetFocus")
	pGetFocus            = user32.NewProc("GetFocus")
	pSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	pLoadCursor          = user32.NewProc("LoadCursorW")
	pLoadImage           = user32.NewProc("LoadImageW")
	pSetTimer            = user32.NewProc("SetTimer")
	pKillTimer           = user32.NewProc("KillTimer")
	pGetSystemMetrics    = user32.NewProc("GetSystemMetrics")
	pSystemParametersInf = user32.NewProc("SystemParametersInfoW")
	pGetDpiForWindow     = user32.NewProc("GetDpiForWindow")
	pGetDpiForSystem     = user32.NewProc("GetDpiForSystem")
	pAdjustWindowRectDpi = user32.NewProc("AdjustWindowRectExForDpi")
	pAdjustWindowRect    = user32.NewProc("AdjustWindowRectEx")
	pCreateMenu          = user32.NewProc("CreateMenu")
	pCreatePopupMenu     = user32.NewProc("CreatePopupMenu")
	pAppendMenu          = user32.NewProc("AppendMenuW")
	pGetClassName        = user32.NewProc("GetClassNameW")
	pIsWindowVisible     = user32.NewProc("IsWindowVisible")
	pGetAncestor         = user32.NewProc("GetAncestor")
	pGetKeyState         = user32.NewProc("GetKeyState")
	pSetCursor           = user32.NewProc("SetCursor")
	pInvalidateRect      = user32.NewProc("InvalidateRect")
	pOpenClipboard       = user32.NewProc("OpenClipboard")
	pCloseClipboard      = user32.NewProc("CloseClipboard")
	pEmptyClipboard      = user32.NewProc("EmptyClipboard")
	pSetClipboardData    = user32.NewProc("SetClipboardData")
	pGetClipboardData    = user32.NewProc("GetClipboardData")
	pGetSysColorBrush    = user32.NewProc("GetSysColorBrush")
	pGetSysColor         = user32.NewProc("GetSysColor")
	pGetCursorPos        = user32.NewProc("GetCursorPos")
	pTrackPopupMenu      = user32.NewProc("TrackPopupMenu")
	pDestroyMenu         = user32.NewProc("DestroyMenu")
	pSetMenu             = user32.NewProc("SetMenu")
	pGetWindowLongPtr    = user32.NewProc("GetWindowLongPtrW")
	pSetWindowLongPtr    = user32.NewProc("SetWindowLongPtrW")

	pCreateFont      = gdi32.NewProc("CreateFontW")
	pDeleteObject    = gdi32.NewProc("DeleteObject")
	pGetStockObject  = gdi32.NewProc("GetStockObject")
	pSetBkMode       = gdi32.NewProc("SetBkMode")
	pSetTextColor    = gdi32.NewProc("SetTextColor")
	pSetBkColor      = gdi32.NewProc("SetBkColor")
	pGetDC           = user32.NewProc("GetDC")
	pReleaseDC       = user32.NewProc("ReleaseDC")
	pSelectObject    = gdi32.NewProc("SelectObject")
	pGetTextExtent32 = gdi32.NewProc("GetTextExtentPoint32W")

	pGetModuleHandle = kernel32.NewProc("GetModuleHandleW")
	pGlobalAlloc     = kernel32.NewProc("GlobalAlloc")
	pGlobalLock      = kernel32.NewProc("GlobalLock")
	pGlobalUnlock    = kernel32.NewProc("GlobalUnlock")

	pInitCommonControlsEx = comctl32.NewProc("InitCommonControlsEx")
	pGetOpenFileName      = comdlg32.NewProc("GetOpenFileNameW")
	pGetSaveFileName      = comdlg32.NewProc("GetSaveFileNameW")
	pCommDlgExtendedError = comdlg32.NewProc("CommDlgExtendedError")
	pSHBrowseForFolder    = shell32.NewProc("SHBrowseForFolderW")
	pSHGetPathFromIDList  = shell32.NewProc("SHGetPathFromIDListW")
	pShellExecute         = shell32.NewProc("ShellExecuteW")
	pCoInitializeEx       = ole32.NewProc("CoInitializeEx")
	pCoTaskMemFree        = ole32.NewProc("CoTaskMemFree")
	pSetWindowTheme       = uxtheme.NewProc("SetWindowTheme")
)

// Fensterstile und Nachrichten (nur, was gebraucht wird)
const (
	wsOverlapped   = 0x00000000
	wsPopup        = 0x80000000
	wsChild        = 0x40000000
	wsVisible      = 0x10000000
	wsDisabled     = 0x08000000
	wsClipSiblings = 0x04000000
	wsClipChildren = 0x02000000
	wsCaption      = 0x00C00000
	wsBorder       = 0x00800000
	wsSysMenu      = 0x00080000
	wsThickFrame   = 0x00040000
	wsMinimizeBox  = 0x00020000
	wsMaximizeBox  = 0x00010000
	wsGroup        = 0x00020000
	wsTabStop      = 0x00010000
	wsVScroll      = 0x00200000
	wsHScroll      = 0x00100000

	wsExClientEdge    = 0x00000200
	wsExDlgModalFrame = 0x00000001
	wsExControlParent = 0x00010000
	wsExAppWindow     = 0x00040000

	swHide        = 0
	swShow        = 5
	swShowNormal  = 1
	swRestore     = 9
	swpNoSize     = 0x0001
	swpNoMove     = 0x0002
	swpNoZOrder   = 0x0004
	swpNoActivate = 0x0010

	wmCreate        = 0x0001
	wmDestroy       = 0x0002
	wmSize          = 0x0005
	wmSetFont       = 0x0030
	wmClose         = 0x0010
	wmNCCreate      = 0x0081
	wmKeyDown       = 0x0100
	wmCommand       = 0x0111
	wmTimer         = 0x0113
	wmNotify        = 0x004E
	wmGetMinMaxInfo = 0x0024
	wmSetIcon       = 0x0080
	wmCtlColorEdit  = 0x0133
	wmCtlColorBtn   = 0x0135
	wmEraseBkgnd    = 0x0014
	wmCtlColorStat  = 0x0138
	wmDpiChanged    = 0x02E0
	wmUser          = 0x0400
	wmApp           = 0x8000
	wmDMGetDefID    = wmUser + 0
	dcHasDefID      = 0x534B

	bsPushButton    = 0x00000000
	bsDefPushButton = 0x00000001
	bsAutoCheckBox  = 0x00000003
	bsAutoRadio     = 0x00000009
	bmGetCheck      = 0x00F0
	bmSetCheck      = 0x00F1
	bmSetStyle      = 0x00F4
	bnClicked       = 0

	esLeft         = 0x0000
	esMultiline    = 0x0004
	esAutoVScroll  = 0x0040
	esAutoHScroll  = 0x0080
	esReadOnly     = 0x0800
	esWantReturn   = 0x1000
	esPassword     = 0x0020
	emSetSel       = 0x00B1
	emLimitText    = 0x00C5
	emSetPwdChar   = 0x00CC
	emSetReadOnly  = 0x00CF
	emSetCueBanner = 0x1501
	emScrollCaret  = 0x00B7

	ssLeft        = 0x00000000
	ssNoPrefix    = 0x00000080
	ssEtchedHorz  = 0x00000010
	ssLeftNoWrap  = 0x0000000C
	ssCenterImage = 0x00000200

	cbsDropDownList = 0x0003
	cbAddString     = 0x0143
	cbGetCurSel     = 0x0147
	cbSetCurSel     = 0x014E
	cbResetContent  = 0x014B
	cbnSelChange    = 1

	lvsReport        = 0x0001
	lvsSingleSel     = 0x0004
	lvsShowSelAlways = 0x0008
	lvsNoColumnHdr   = 0x4000
	lvsNoSortHeader  = 0x8000
	lvmFirst         = 0x1000
	lvmDeleteAll     = lvmFirst + 9
	lvmGetNextItem   = lvmFirst + 12
	lvmSetColWidth   = lvmFirst + 30
	lvmGetItemCount  = lvmFirst + 4
	lvmInsertItem    = lvmFirst + 77
	lvmSetItemText   = lvmFirst + 116
	lvmInsertColumn  = lvmFirst + 97
	lvmSetExStyle    = lvmFirst + 54
	lvmSetItemState  = lvmFirst + 43
	lvmEnsureVisible = lvmFirst + 19
	lvmGetItemText   = lvmFirst + 115
	lvsExFullRowSel  = 0x00000020
	lvsExDoubleBuf   = 0x00010000
	lvsExLabelTip    = 0x00004000
	lvifText         = 0x0001
	lvifState        = 0x0008
	lvcfFmt          = 0x0001
	lvcfWidth        = 0x0002
	lvcfText         = 0x0004
	lvcfSubItem      = 0x0008
	lvcfmtLeft       = 0x0000
	lvcfmtRight      = 0x0001
	lvisSelected     = 0x0002
	lvisFocused      = 0x0001
	lvniSelected     = 0x0002
	lvnFirst         = ^uint32(99) // -100
	lvnItemChanged   = lvnFirst - 1
	lvnItemActivate  = lvnFirst - 14
	nmDblClk         = ^uint32(2) // -3
	nmFirst0         = 0

	pbsMarquee   = 0x08
	pbsSmooth    = 0x01
	pbmSetMarq   = wmUser + 10
	pbmSetPos    = wmUser + 2
	pbmSetRange  = wmUser + 6
	sbarsGrip    = 0x0100
	sbSetTextW   = wmUser + 11
	sbSimple     = wmUser + 9
	iccListView  = 0x00000001
	iccBar       = 0x00000004
	iccProgress  = 0x00000020
	iccStandard  = 0x00004000
	iccTabs      = 0x00000008
	vkF5         = 0x74
	vkReturn     = 0x0D
	vkEscape     = 0x1B
	vkControl    = 0x11
	vkDelete     = 0x2E
	mfString     = 0x0000
	mfSeparator  = 0x0800
	mfPopup      = 0x0010
	mfGrayed     = 0x0001
	mbOK         = 0x00000000
	mbYesNo      = 0x00000004
	mbIconError  = 0x00000010
	mbIconQuest  = 0x00000020
	mbIconWarn   = 0x00000030
	mbIconInfo   = 0x00000040
	mbDefButton2 = 0x00000100
	idYes        = 6
	idNo         = 7
	cfUnicodeTxt = 13
	gmemMoveable = 0x0002

	gwlStyle     = ^uintptr(15) // GWL_STYLE (-16)
	colorWindow  = 5
	colorBtnFace = 15
	whiteBrush   = 0
	transparent  = 1
	imageIcon    = 1
	lrDefault    = 0x00000040
	lrShared     = 0x00008000
	smCxIcon     = 11
	smCyIcon     = 12
	smCxSmIcon   = 49
	smCySmIcon   = 50
	smCxScreen   = 0
	smCyScreen   = 1
	spiGetWork   = 0x0030
	gaRoot       = 2
	idcArrow     = 32512
	fwNormal     = 400
	fwSemiBold   = 600
	fwBold       = 700
	cwUseDefault = 0x80000000
	hwndMessage  = ^uintptr(2) // HWND_MESSAGE (-3)

	ofnFileMustExist  = 0x00001000
	ofnPathMustExist  = 0x00000800
	ofnOverwritePromt = 0x00000002
	ofnHideReadOnly   = 0x00000004
	ofnExplorer       = 0x00080000
	ofnNoChangeDir    = 0x00000008
	ofnAllowMulti     = 0x00000200

	bifReturnOnlyFSDirs = 0x0001
	bifEditBox          = 0x0010
	bifNewDialogStyle   = 0x0040
	bifUseNewUI         = bifNewDialogStyle | bifEditBox
	bffmInitialized     = 1
	bffmSetSelectionW   = wmUser + 103
	coinitApartment     = 0x2
)

type (
	point struct{ X, Y int32 }
	rect  struct{ Left, Top, Right, Bottom int32 }

	msgT struct {
		Hwnd    windows.HWND
		Message uint32
		WParam  uintptr
		LParam  uintptr
		Time    uint32
		Pt      point
	}

	wndClassEx struct {
		Size       uint32
		Style      uint32
		WndProc    uintptr
		ClsExtra   int32
		WndExtra   int32
		Instance   windows.Handle
		Icon       windows.Handle
		Cursor     windows.Handle
		Background windows.Handle
		MenuName   *uint16
		ClassName  *uint16
		IconSm     windows.Handle
	}

	nmhdr struct {
		HwndFrom windows.HWND
		IDFrom   uintptr
		Code     uint32
	}

	nmListView struct {
		Hdr      nmhdr
		Item     int32
		SubItem  int32
		NewState uint32
		OldState uint32
		Changed  uint32
		Action   point
		LParam   uintptr
	}

	nmItemActivate struct {
		Hdr      nmhdr
		Item     int32
		SubItem  int32
		NewState uint32
		OldState uint32
		Changed  uint32
		Action   point
		LParam   uintptr
		KeyFlags uint32
	}

	lvColumn struct {
		Mask       uint32
		Fmt        int32
		Cx         int32
		Text       *uint16
		CchTextMax int32
		SubItem    int32
		Image      int32
		Order      int32
	}

	lvItem struct {
		Mask       uint32
		Item       int32
		SubItem    int32
		State      uint32
		StateMask  uint32
		Text       *uint16
		CchTextMax int32
		Image      int32
		LParam     uintptr
		Indent     int32
	}

	minMaxInfo struct {
		Reserved     point
		MaxSize      point
		MaxPosition  point
		MinTrackSize point
		MaxTrackSize point
	}

	initCommonControlsEx struct{ Size, ICC uint32 }

	openFileName struct {
		StructSize    uint32
		Owner         windows.HWND
		Instance      windows.Handle
		Filter        *uint16
		CustomFilter  *uint16
		MaxCustFilter uint32
		FilterIndex   uint32
		File          *uint16
		MaxFile       uint32
		FileTitle     *uint16
		MaxFileTitle  uint32
		InitialDir    *uint16
		Title         *uint16
		Flags         uint32
		FileOffset    uint16
		FileExtension uint16
		DefExt        *uint16
		CustData      uintptr
		Hook          uintptr
		TemplateName  *uint16
		Reserved      uintptr
		Reserved2     uint32
		FlagsEx       uint32
	}

	browseInfo struct {
		Owner       windows.HWND
		Root        uintptr
		DisplayName *uint16
		Title       *uint16
		Flags       uint32
		Callback    uintptr
		LParam      uintptr
		Image       int32
	}
)

// ---------- kleine Hilfen ----------

// u16 wandelt Text in UTF-16 (ohne eingebettete Nullzeichen).
func u16(s string) *uint16 {
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", "")
	}
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

func loword(v uintptr) int { return int(v & 0xFFFF) }
func hiword(v uintptr) int { return int((v >> 16) & 0xFFFF) }

func sendMsg(h windows.HWND, m uint32, w, l uintptr) uintptr {
	r, _, _ := pSendMessage.Call(uintptr(h), uintptr(m), w, l)
	return r
}

func sendPtr(h windows.HWND, m uint32, w uintptr, p unsafe.Pointer) uintptr {
	r, _, _ := pSendMessage.Call(uintptr(h), uintptr(m), w, uintptr(p))
	return r
}

func sendStr(h windows.HWND, m uint32, w uintptr, s string) uintptr {
	p := u16(s)
	r, _, _ := pSendMessage.Call(uintptr(h), uintptr(m), w, uintptr(unsafe.Pointer(p)))
	return r
}

func postMsg(h windows.HWND, m uint32, w, l uintptr) {
	_, _, _ = pPostMessage.Call(uintptr(h), uintptr(m), w, l)
}

func hInstance() windows.Handle {
	h, _, _ := pGetModuleHandle.Call(0)
	return windows.Handle(h)
}

func getText(h windows.HWND) string {
	n, _, _ := pGetWindowTextLength.Call(uintptr(h))
	if n == 0 {
		return ""
	}
	buf := make([]uint16, n+1)
	_, _, _ = pGetWindowText.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return windows.UTF16ToString(buf)
}

func setText(h windows.HWND, s string) {
	p := u16(s)
	_, _, _ = pSetWindowText.Call(uintptr(h), uintptr(unsafe.Pointer(p)))
}

func className(h windows.HWND) string {
	buf := make([]uint16, 64)
	n, _, _ := pGetClassName.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return windows.UTF16ToString(buf[:n])
}

func getRect(h windows.HWND, client bool) rect {
	var r rect
	if client {
		_, _, _ = pGetClientRect.Call(uintptr(h), uintptr(unsafe.Pointer(&r)))
	} else {
		_, _, _ = pGetWindowRect.Call(uintptr(h), uintptr(unsafe.Pointer(&r)))
	}
	return r
}

func toCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

func fromCRLF(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}

func screenWork() rect {
	var r rect
	_, _, _ = pSystemParametersInf.Call(spiGetWork, 0, uintptr(unsafe.Pointer(&r)), 0)
	if r.Right == 0 {
		w, _, _ := pGetSystemMetrics.Call(smCxScreen)
		h, _, _ := pGetSystemMetrics.Call(smCyScreen)
		r = rect{0, 0, int32(w), int32(h)}
	}
	return r
}

func systemDPI() int {
	if pGetDpiForSystem.Find() == nil {
		if d, _, _ := pGetDpiForSystem.Call(); d >= 96 {
			return int(d)
		}
	}
	return 96
}

func windowDPI(h windows.HWND) int {
	if pGetDpiForWindow.Find() == nil {
		if d, _, _ := pGetDpiForWindow.Call(uintptr(h)); d >= 96 {
			return int(d)
		}
	}
	return systemDPI()
}

// setClipboardText legt Text in die Zwischenablage.
func setClipboardText(owner windows.HWND, s string) bool {
	u, err := windows.UTF16FromString(s)
	if err != nil {
		return false
	}
	if r, _, _ := pOpenClipboard.Call(uintptr(owner)); r == 0 {
		return false
	}
	defer pCloseClipboard.Call()
	_, _, _ = pEmptyClipboard.Call()
	size := uintptr(len(u) * 2)
	hMem, _, _ := pGlobalAlloc.Call(gmemMoveable, size)
	if hMem == 0 {
		return false
	}
	p, _, _ := pGlobalLock.Call(hMem)
	if p == 0 {
		return false
	}
	copy(unsafe.Slice((*uint16)(ptrOf(p)), len(u)), u)
	_, _, _ = pGlobalUnlock.Call(hMem)
	r, _, _ := pSetClipboardData.Call(cfUnicodeTxt, hMem)
	return r != 0
}

// getClipboardText liest Text aus der Zwischenablage.
func getClipboardText(owner windows.HWND) string {
	if r, _, _ := pOpenClipboard.Call(uintptr(owner)); r == 0 {
		return ""
	}
	defer pCloseClipboard.Call()
	h, _, _ := pGetClipboardData.Call(cfUnicodeTxt)
	if h == 0 {
		return ""
	}
	p, _, _ := pGlobalLock.Call(h)
	if p == 0 {
		return ""
	}
	defer pGlobalUnlock.Call(h)
	var n int
	for ; n < 1<<24; n++ {
		if *(*uint16)(ptrOf(p + uintptr(n)*2)) == 0 {
			break
		}
	}
	return windows.UTF16ToString(unsafe.Slice((*uint16)(ptrOf(p)), n))
}

// shellOpen öffnet einen Ordner, eine Datei oder eine Webadresse mit dem Standardprogramm.
func shellOpen(target string) {
	_, _, _ = pShellExecute.Call(0, uintptr(unsafe.Pointer(u16("open"))), uintptr(unsafe.Pointer(u16(target))), 0, 0, swShowNormal)
}
