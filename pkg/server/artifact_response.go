package server

import (
	"io"
	"mime"
	"os"
	"strconv"

	"github.com/gofiber/fiber/v3"
)

// sendArtifactFile takes ownership of f on every path. Preview pages are exact
// byte intervals (not necessarily complete UTF-8 strings or JSONL records).
// Downloads intentionally bypass preview limits but remain streamed and bound
// to the file length observed at open time, so a growing log cannot keep a
// download alive indefinitely. This is not an immutable snapshot of an active
// file: clients archiving a run should prefer terminal runs.
func sendArtifactFile(c fiber.Ctx, f *os.File, info os.FileInfo) error {
	download := c.Query("download") == "1"
	offset := int64(0)
	if raw := c.Query("offset"); raw != "" {
		var err error
		offset, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || offset < 0 || offset > info.Size() || download {
			_ = f.Close()
			return respondErrorMsg(c, fiber.StatusBadRequest, "invalid artifact offset (not supported for downloads)")
		}
	}
	if offset != 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			_ = f.Close()
			return respondErrorMsg(c, fiber.StatusInternalServerError, "failed to seek artifact")
		}
	}

	sendSize := info.Size() - offset
	if !download {
		sendSize = min(sendSize, queryByteLimit(c, maxArtifactReadBytes, maxArtifactReadBytesHardCap))
	}
	truncated := "0"
	if offset != 0 || sendSize < info.Size() {
		truncated = "1"
	}
	c.Set("X-Artifact-Total-Size", strconv.FormatInt(info.Size(), 10))
	c.Set("X-Artifact-Truncated", truncated)
	c.Set("X-Artifact-Offset", strconv.FormatInt(offset, 10))
	c.Set("X-Artifact-Returned-Bytes", strconv.FormatInt(sendSize, 10))
	c.Set("Cache-Control", "no-store")
	c.Set("Content-Type", artifactContentType(info.Name()))
	if download {
		c.Set("Content-Type", "application/octet-stream")
		c.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": info.Name()}))
	}
	if sendSize == 0 {
		_ = f.Close()
		return c.Send(nil)
	}
	// fasthttp closes the reader once the response finishes or is reset.
	return c.SendStream(&closingLimitReader{R: io.LimitReader(f, sendSize), C: f}, int(sendSize))
}
