package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"golang.zx2c4.com/wireguard/device"
)

const redactedLogValue = "[REDACTED]"

type appLogger struct {
	logger *slog.Logger
}

func newAppLogger(w io.Writer, debug bool) *appLogger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.TimeKey {
				return slog.Attr{}
			}
			if sensitiveLogKey(attr.Key) {
				return slog.String(attr.Key, redactedLogValue)
			}
			return attr
		},
	})
	return &appLogger{logger: slog.New(handler)}
}

func sensitiveLogKey(key string) bool {
	key = strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	for _, part := range []string{"secret", "token", "credential", "private_key", "authorization"} {
		if strings.Contains(key, part) {
			return true
		}
	}
	return false
}

func (l *appLogger) IsDebug() bool                     { return l.logger.Enabled(context.Background(), slog.LevelDebug) }
func (l *appLogger) Debug(message string, args ...any) { l.logger.Debug(message, args...) }
func (l *appLogger) Info(message string, args ...any)  { l.logger.Info(message, args...) }
func (l *appLogger) Warn(message string, args ...any)  { l.logger.Warn(message, args...) }
func (l *appLogger) Error(message string, args ...any) { l.logger.Error(message, args...) }

var appLog = newAppLogger(io.Discard, false)

func newWireGuardLogger(l *appLogger, debug bool) *device.Logger {
	logger := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf: func(format string, args ...any) {
			l.Error("WireGuard", "detail", strings.TrimSpace(fmt.Sprintf(format, args...)))
		},
	}
	if debug {
		logger.Verbosef = func(format string, args ...any) {
			l.Debug("WireGuard", "detail", strings.TrimSpace(fmt.Sprintf(format, args...)))
		}
	}
	return logger
}
