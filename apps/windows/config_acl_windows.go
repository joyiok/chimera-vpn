//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// restrictFileACL replaces the file's DACL with one that grants only the
// current user full control. NTFS ignores POSIX modes, so the 0600 in
// saveConfig is a no-op on Windows: without this the seed/PSK config file
// inherits the install directory's ACLs and may be readable by every local
// account.
func restrictFileACL(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("open process token: %w", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("get token user: %w", err)
	}
	sd, err := windows.SecurityDescriptorFromString(
		fmt.Sprintf("D:P(A;;FA;;;%s)", user.User.Sid.String()))
	if err != nil {
		return fmt.Errorf("build security descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("extract DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		return fmt.Errorf("set DACL: %w", err)
	}
	return nil
}
