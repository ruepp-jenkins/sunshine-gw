//go:build linux

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// disableEcho switches terminal echo off and returns the function that switches it back on.
//
// Done with the TCGETS/TCSETS ioctls directly rather than with golang.org/x/term: the
// module has no dependencies, which is what lets the image build run without downloading
// anything but the base images. The gateway only ever runs on Linux, and the fallback in
// termios_other.go keeps a build for anything else compiling.
func disableEcho(f *os.File) (restore func(), err error) {
	fd := f.Fd()
	var saved syscall.Termios
	if err := ioctlTermios(fd, syscall.TCGETS, &saved); err != nil {
		return nil, errNoEchoControl
	}
	quiet := saved
	quiet.Lflag &^= syscall.ECHO
	if err := ioctlTermios(fd, syscall.TCSETS, &quiet); err != nil {
		return nil, errNoEchoControl
	}
	return func() {
		_ = ioctlTermios(fd, syscall.TCSETS, &saved)
	}, nil
}

func ioctlTermios(fd uintptr, request uintptr, termios *syscall.Termios) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request,
		uintptr(unsafe.Pointer(termios))); errno != 0 {
		return errno
	}
	return nil
}
