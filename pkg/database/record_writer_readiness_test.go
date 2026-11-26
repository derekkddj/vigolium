package database

import (
	"sync"
	"testing"
)

func TestRecordWriterAcceptingTracksShutdown(t *testing.T) {
	var absent *RecordWriter
	if absent.Accepting() || new(RecordWriter).Accepting() {
		t.Fatal("an absent or uninitialized writer must not advertise admission")
	}
	writer := NewRecordWriter(NewRepository(newTestDB(t)), RecordWriterConfig{})
	t.Cleanup(writer.Close)
	if !writer.Accepting() {
		t.Fatal("new writer is not accepting")
	}
	var readers sync.WaitGroup
	start := make(chan struct{})
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			<-start
			for range 100 {
				_ = writer.Accepting()
			}
		}()
	}
	close(start)
	writer.Close()
	readers.Wait()
	if writer.Accepting() {
		t.Fatal("closed writer still advertises admission")
	}
}
