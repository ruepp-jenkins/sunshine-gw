package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// errNoEchoControl means the terminal's echo could not be switched off, so the password
// would be typed in plain view.
var errNoEchoControl = errors.New("Echo des Terminals nicht steuerbar")

// readPassword obtains the password for the hash-password subcommand.
//
// On a terminal it reads one line - ending at Enter, which is what a person expects - and
// asks twice, because a typo in a hash is only noticed at the login prompt later. Piped
// input is read to EOF instead, so `printf '%s' pw | gateway hash-password` keeps working
// in a script.
func readPassword() (string, error) {
	fi, err := os.Stdin.Stat()
	interactive := err == nil && fi.Mode()&os.ModeCharDevice != 0
	if !interactive {
		return readPipedPassword(os.Stdin)
	}

	reader := bufio.NewReader(os.Stdin)
	first, err := readLineHidden(reader, "Passwort: ")
	if err != nil {
		return "", err
	}
	second, err := readLineHidden(reader, "Wiederholen: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("die beiden Eingaben stimmen nicht ueberein")
	}
	return first, nil
}

// readPipedPassword takes everything up to EOF and drops the trailing newline a shell adds.
func readPipedPassword(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, 4096))
	if err != nil {
		return "", err
	}
	password := strings.TrimRight(string(b), "\r\n")
	if password == "" {
		return "", errors.New("kein Passwort auf der Standardeingabe")
	}
	return password, nil
}

func readLineHidden(reader *bufio.Reader, prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	restore, err := disableEcho(os.Stdin)
	switch {
	case errors.Is(err, errNoEchoControl):
		fmt.Fprint(os.Stderr, "(sichtbar) ")
	case err != nil:
		return "", err
	default:
		// A Ctrl-C between here and the restore below would leave the terminal with echo
		// switched off, so the signal is caught for exactly that stretch.
		stop := make(chan struct{})
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			select {
			case <-sig:
				restore()
				fmt.Fprintln(os.Stderr)
				os.Exit(130)
			case <-stop:
			}
		}()
		defer func() {
			restore()
			signal.Stop(sig)
			close(stop)
			fmt.Fprintln(os.Stderr)
		}()
	}

	line, err := reader.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		if err == io.EOF {
			return "", errors.New("Eingabe abgebrochen")
		}
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
