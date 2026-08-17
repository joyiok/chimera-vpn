//go:build windows

package main

import (
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wmApp           = 0x8000
	wmTray          = wmApp + 1
	wmLButtonUp     = 0x0202
	wmRButtonUp     = 0x0205
	wmLButtonDblClk = 0x0203
	wmCommand       = 0x0111
	wmDestroy       = 0x0002

	nimAdd     = 0x00000000
	nimDelete  = 0x00000002
	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004

	idiApplication = 32512
	mfString       = 0x00000000
	mfSeparator    = 0x00000800
	tpmRightButton = 0x0002
	tpmBottomAlign = 0x0020
	tpmRightAlign  = 0x0008

	idShow       = 1001
	idConnect    = 1002
	idDisconnect = 1003
	idQuit       = 1004
)

type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     windows.Handle
	HIcon         windows.Handle
	HCursor       windows.Handle
	HbrBackground windows.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       windows.Handle
}

type notifyIconData struct {
	CbSize           uint32
	Hwnd             windows.Handle
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            windows.Handle
	SzTip            [128]uint16
}

type point struct {
	X, Y int32
}

type msg struct {
	Hwnd    windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

var (
	moduser32   = windows.NewLazySystemDLL("user32.dll")
	modshell32  = windows.NewLazySystemDLL("shell32.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassExW    = moduser32.NewProc("RegisterClassExW")
	procCreateWindowExW     = moduser32.NewProc("CreateWindowExW")
	procDefWindowProcW      = moduser32.NewProc("DefWindowProcW")
	procGetMessageW         = moduser32.NewProc("GetMessageW")
	procTranslateMessage    = moduser32.NewProc("TranslateMessage")
	procDispatchMessageW    = moduser32.NewProc("DispatchMessageW")
	procPostQuitMessage     = moduser32.NewProc("PostQuitMessage")
	procLoadIconW           = moduser32.NewProc("LoadIconW")
	procCreatePopupMenu     = moduser32.NewProc("CreatePopupMenu")
	procAppendMenuW         = moduser32.NewProc("AppendMenuW")
	procTrackPopupMenu      = moduser32.NewProc("TrackPopupMenu")
	procDestroyMenu         = moduser32.NewProc("DestroyMenu")
	procSetForegroundWindow = moduser32.NewProc("SetForegroundWindow")
	procGetCursorPos        = moduser32.NewProc("GetCursorPos")
	procDestroyWindow       = moduser32.NewProc("DestroyWindow")
	procPostMessageW        = moduser32.NewProc("PostMessageW")
	procShellNotifyIconW    = modshell32.NewProc("Shell_NotifyIconW")
	procGetModuleHandleW    = modkernel32.NewProc("GetModuleHandleW")
)

var (
	trayApp     *ChimeraApp
	trayHWND    windows.Handle
	trayNID     notifyIconData
	trayWndProc = syscall.NewCallback(trayWndProc)
)

func startTray(a *ChimeraApp) {
	trayApp = a
	go runTray()
}

func stopTray() {
	if trayHWND != 0 {
		procPostMessageW.Call(uintptr(trayHWND), wmDestroy, 0, 0)
	}
}

func runTray() {
	className, _ := windows.UTF16PtrFromString("ChimeraTrayClass")
	inst, _, _ := procGetModuleHandleW.Call(0)
	icon, _, _ := procLoadIconW.Call(0, uintptr(idiApplication))

	wc := wndClassEx{
		LpfnWndProc:   trayWndProc,
		HInstance:     windows.Handle(inst),
		HIcon:         windows.Handle(icon),
		LpszClassName: className,
	}
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	if r, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		log.Printf("[tray] RegisterClassEx: %v", err)
		return
	}

	title, _ := windows.UTF16PtrFromString("CHIMERA")
	hwnd, _, err := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(title)), 0, 0, 0, 0, 0, 0, 0, inst, 0)
	if hwnd == 0 {
		log.Printf("[tray] CreateWindowEx: %v", err)
		return
	}
	trayHWND = windows.Handle(hwnd)

	nid := notifyIconData{
		Hwnd:             trayHWND,
		UID:              1,
		UFlags:           nifMessage | nifIcon | nifTip,
		UCallbackMessage: wmTray,
		HIcon:            windows.Handle(icon),
	}
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	copyUTF16(nid.SzTip[:], "CHIMERA")
	trayNID = nid
	if r, _, err := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid))); r == 0 {
		log.Printf("[tray] Shell_NotifyIcon add: %v", err)
		return
	}

	var m msg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&trayNID)))
}

func trayWndProc(hwnd windows.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmTray:
		switch lParam {
		case wmLButtonUp, wmLButtonDblClk:
			if trayApp != nil {
				runtimeWindowShow(trayApp.ctx)
			}
		case wmRButtonUp:
			showTrayMenu(hwnd)
		}
		return 0
	case wmCommand:
		handleTrayCommand(uint16(wParam))
		return 0
	case wmDestroy:
		procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&trayNID)))
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

func showTrayMenu(hwnd windows.Handle) {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	appendMenu(menu, mfString, idShow, "显示窗口")
	appendMenu(menu, mfString, idConnect, "连接")
	appendMenu(menu, mfString, idDisconnect, "断开")
	appendMenu(menu, mfSeparator, 0, "")
	appendMenu(menu, mfString, idQuit, "退出")

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(uintptr(hwnd))
	procTrackPopupMenu.Call(menu, tpmRightButton|tpmBottomAlign|tpmRightAlign, uintptr(pt.X), uintptr(pt.Y), 0, uintptr(hwnd), 0)
	procDestroyMenu.Call(menu)
}

func appendMenu(menu uintptr, flags, id uint32, text string) {
	p, _ := windows.UTF16PtrFromString(text)
	procAppendMenuW.Call(menu, uintptr(flags), uintptr(id), uintptr(unsafe.Pointer(p)))
}

func handleTrayCommand(id uint16) {
	if trayApp == nil {
		return
	}
	switch id {
	case idShow:
		runtimeWindowShow(trayApp.ctx)
	case idConnect:
		trayApp.mu.Lock()
		cfg := trayApp.cfg
		trayApp.mu.Unlock()
		go func() {
			if err := trayApp.Start(cfg.SeedHex, cfg.Generation, cfg.PSKHex, cfg.ServerAddr); err != nil {
				log.Printf("[tray] connect: %v", err)
			}
		}()
	case idDisconnect:
		go func() { _ = trayApp.Stop() }()
	case idQuit:
		trayApp.QuitApp()
	}
}

func copyUTF16(dst []uint16, s string) {
	p, _ := windows.UTF16FromString(s)
	n := len(p)
	if n > len(dst) {
		n = len(dst)
	}
	copy(dst, p[:n])
}
