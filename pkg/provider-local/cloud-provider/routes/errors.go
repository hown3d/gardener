package routes

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

type processError struct {
	code   int
	stderr io.Reader
	stdout io.Reader
}

func (e processError) Error() string {
	stdout, err := io.ReadAll(e.stdout)
	if err != nil {
		return err.Error()
	}

	stderr, err := io.ReadAll(e.stderr)
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("process exit with code %d\nstderr:\n%s\nstdout:\n%s\n", e.code, stderr, stdout)
}

func isFileAlreadyExists(err error) bool {
	processErr, ok := errors.AsType[processError](err)
	if !ok {
		return false
	}
	stdout, err := processErrorStderr(&processErr)
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(stdout)) == "RTNETLINK answers: File exists"
}

func processErrorStderr(perr *processError) ([]byte, error) {
	cacheBuffer := new(bytes.Buffer)
	// TeeReader returns a Reader that writes to cacheBuffer whatever it reads from originalReader.
	stderr := io.TeeReader(perr.stderr, cacheBuffer)
	stdout, err := io.ReadAll(stderr)
	if err != nil {
		return nil, err
	}
	perr.stderr = cacheBuffer
	return stdout, err
}

func isAddressAlreadyAssigned(err error) bool {
	processErr, ok := errors.AsType[processError](err)
	if !ok {
		return false
	}
	stdout, err := processErrorStderr(&processErr)
	if err != nil {
		return false
	}
	return strings.Contains(strings.TrimSpace(string(stdout)), "Address already assigned")
}
