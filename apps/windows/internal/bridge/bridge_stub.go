//go:build !windows

package bridge

import "errors"

func platformStart(ip string, mtu int, send Sender, recv Receiver) (*Bridge, error) {
	return nil, errors.New("packet bridge is only available on Windows (Wintun data plane)")
}
