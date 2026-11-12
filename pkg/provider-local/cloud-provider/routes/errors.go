package routes

import (
	"errors"
	"fmt"
	"strings"
)

type processError struct {
	code   int
	stderr []byte
	stdout []byte
}

func (e processError) Error() string {
	return fmt.Sprintf("process exit with code %d\nstderr:\n%s\nstdout:\n%s\n", e.code, e.stderr, e.stdout)
}

func isFileAlreadyExists(err error) bool {
	processErr, ok := errors.AsType[processError](err)
	if !ok {
		return false
	}
	return strings.TrimSpace(string(processErr.stderr)) == "RTNETLINK answers: File exists"
}

func isAddressAlreadyAssigned(err error) bool {
	processErr, ok := errors.AsType[processError](err)
	if !ok {
		return false
	}
	return strings.Contains(strings.TrimSpace(string(processErr.stderr)), "Address already assigned")
}

func isNoSuchProcess(err error) bool {
	processErr, ok := errors.AsType[processError](err)
	if !ok {
		return false
	}
	return strings.TrimSpace(string(processErr.stderr)) == "RTNETLINK answers: No such process"
}
