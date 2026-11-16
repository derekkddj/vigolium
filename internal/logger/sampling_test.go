package logger

import (
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestSamplingPreservesEveryWarningAndError(t *testing.T) {
	base, observed := observer.New(zapcore.DebugLevel)
	core := sampleLowPriority(base).With([]zapcore.Field{zap.String("scan_uuid", "fixture")})
	for _, level := range []zapcore.Level{zapcore.DebugLevel, zapcore.InfoLevel, zapcore.WarnLevel, zapcore.ErrorLevel} {
		for i := 0; i < 305; i++ {
			// Fixed entry time avoids crossing a real sampling tick in a slow
			// CI run and makes exact retained counts deterministic.
			entry := zapcore.Entry{Level: level, Time: time.Unix(10000, 0), Message: level.String()}
			if checked := core.Check(entry, nil); checked != nil {
				checked.Write()
			}
		}
		want := 8 // first five, then every hundredth of the remaining 300
		if level >= zapcore.WarnLevel {
			want = 305
		}
		entries := observed.FilterLevelExact(level).All()
		if len(entries) != want {
			t.Fatalf("level=%s retained=%d want=%d", level, len(entries), want)
		}
		for _, entry := range entries {
			if entry.ContextMap()["scan_uuid"] != "fixture" {
				t.Fatalf("With lost context: %+v", entry)
			}
		}
	}
}

func TestSamplingDoesNotEnableDisabledLevels(t *testing.T) {
	base, observed := observer.New(zapcore.ErrorLevel)
	core := sampleLowPriority(base)
	for _, level := range []zapcore.Level{zapcore.DebugLevel, zapcore.InfoLevel, zapcore.WarnLevel} {
		if core.Enabled(level) || core.Check(zapcore.Entry{Level: level}, nil) != nil {
			t.Fatalf("sampling enabled %s below configured threshold", level)
		}
	}
	if observed.Len() != 0 {
		t.Fatal("disabled entries were written")
	}
}
