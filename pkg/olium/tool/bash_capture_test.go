package tool

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type bashReadFailure struct{}

func (bashReadFailure) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestBashCaptureReadFromTracksTrueEOFAndReadFailure(t *testing.T) {
	for _, failed := range []bool{false, true} {
		capture := &bashCapture{}
		stdout := bashCaptureWriter{capture: capture, stream: "stdout"}
		stderr := bashCaptureWriter{capture: capture, stream: "stderr"}
		var input io.Reader = bytes.NewReader([]byte("prefix"))
		if failed {
			input = io.MultiReader(input, bashReadFailure{})
		}
		n, err := stdout.ReadFrom(input)
		if n != 6 || (failed && !errors.Is(err, io.ErrUnexpectedEOF)) || (!failed && err != nil) {
			t.Fatal("pipe prefix or read failure lost")
		}
		if _, err := stderr.ReadFrom(bytes.NewReader(nil)); err != nil {
			t.Fatal(err)
		}
		if capture.details()["output_capture_complete"] != !failed {
			t.Fatal("non-EOF pipe termination falsely claimed complete capture")
		}
	}
}
