//go:build !linux

package main

import "os"

// disableEcho has no implementation outside Linux; the caller then says the input is
// visible rather than refusing to work.
func disableEcho(f *os.File) (restore func(), err error) {
	return nil, errNoEchoControl
}
