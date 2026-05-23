package tun

import (
	"fmt"
	"os"
)

type stdLogger struct{}

func (l stdLogger) Trace(args ...any) {
	fmt.Fprint(os.Stderr, "[trace] ")
	fmt.Fprintln(os.Stderr, args...)
}
func (l stdLogger) Debug(args ...any) {
	fmt.Fprint(os.Stderr, "[debug] ")
	fmt.Fprintln(os.Stderr, args...)
}
func (l stdLogger) Info(args ...any) {
	fmt.Fprint(os.Stderr, "[info] ")
	fmt.Fprintln(os.Stderr, args...)
}
func (l stdLogger) Warn(args ...any) {
	fmt.Fprint(os.Stderr, "[warn] ")
	fmt.Fprintln(os.Stderr, args...)
}
func (l stdLogger) Error(args ...any) {
	fmt.Fprint(os.Stderr, "[error] ")
	fmt.Fprintln(os.Stderr, args...)
}
func (l stdLogger) Fatal(args ...any) {
	fmt.Fprint(os.Stderr, "[fatal] ")
	fmt.Fprintln(os.Stderr, args...)
	os.Exit(1)
}
func (l stdLogger) Panic(args ...any) { msg := fmt.Sprintln(args...); panic(msg) }
