//go:build windows

package bridge

import "golang.org/x/sys/windows"

// sysProcAttr hides console windows spawned for netsh. The application must
// run elevated (or netsh itself must be run once by an administrator).
var sysProcAttr = windows.SysProcAttr{HideWindow: true}
