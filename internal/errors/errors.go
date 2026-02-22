package errors

import "fmt"

// ─── types ────────────────────────────────────────────────────────────────────

type PermissionError struct {
	Message string
}

type NetworkError struct {
	Target  string
	Message string
}

type InputError struct {
	Field   string
	Message string
}

// ─── error interfaces ─────────────────────────────────────────────────────────

func (e *PermissionError) Error() string {
	return fmt.Sprintf("permission denied: %s\n  hint: run with sudo", e.Message)
}

func (e *NetworkError) Error() string {
	if e.Target != "" {
		return fmt.Sprintf("network error [%s]: %s", e.Target, e.Message)
	}
	return fmt.Sprintf("network error: %s", e.Message)
}

func (e *InputError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("invalid %s: %s", e.Field, e.Message)
	}
	return fmt.Sprintf("input error: %s", e.Message)
}

// ─── constructors ─────────────────────────────────────────────────────────────

func Permission(msg string) error {
	return &PermissionError{Message: msg}
}

func Network(target, msg string) error {
	return &NetworkError{Target: target, Message: msg}
}

func Input(field, msg string) error {
	return &InputError{Field: field, Message: msg}
}
