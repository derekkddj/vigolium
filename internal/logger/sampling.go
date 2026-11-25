package logger

import (
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// levelFilterCore filters before Check forwards an entry to the underlying
// core. Embedding Core without overriding Check would allow excluded levels
// back into a tee and write high-priority entries twice.
type levelFilterCore struct {
	zapcore.Core
	allow zapcore.LevelEnabler
}

func (c levelFilterCore) Enabled(level zapcore.Level) bool {
	return c.allow.Enabled(level) && c.Core.Enabled(level)
}

func (c levelFilterCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if !c.Enabled(entry.Level) {
		return checked
	}
	return c.Core.Check(entry, checked)
}

func (c levelFilterCore) With(fields []zapcore.Field) zapcore.Core {
	return levelFilterCore{Core: c.Core.With(fields), allow: c.allow}
}

func sampleLowPriority(core zapcore.Core) zapcore.Core {
	low := levelFilterCore{Core: core, allow: zap.LevelEnablerFunc(func(level zapcore.Level) bool {
		return level < zapcore.WarnLevel
	})}
	high := levelFilterCore{Core: core, allow: zap.LevelEnablerFunc(func(level zapcore.Level) bool {
		return level >= zapcore.WarnLevel
	})}
	return zapcore.NewTee(zapcore.NewSamplerWithOptions(low, time.Second, 5, 100), high)
}
