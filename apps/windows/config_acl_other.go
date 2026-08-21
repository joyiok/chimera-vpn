//go:build !windows

package main

// restrictFileACL is a no-op off Windows: POSIX platforms enforce the
// 0600 mode set by saveConfig directly.
func restrictFileACL(path string) error { return nil }
