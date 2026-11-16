package fastdialer

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Mzack9999/gcache"
	"github.com/projectdiscovery/fastdialer/fastdialer/utils"
)

// Pause Get AFTER it captures the old pointer and BEFORE Remove. This is the
// dangerous check/remove window: another publisher must not Set in between.
// Embedding retains the real cache for all operations except this test barrier.
type pausedEvictionCache struct {
	gcache.Cache[string, *utils.DialWrap]
	readOld  chan struct{}
	release  chan struct{}
	set      chan struct{}
	pauseOne sync.Once
}

func (c *pausedEvictionCache) GetIFPresent(key string) (*utils.DialWrap, error) {
	value, err := c.Cache.GetIFPresent(key)
	c.pauseOne.Do(func() {
		close(c.readOld)
		<-c.release
	})
	return value, err
}

func (c *pausedEvictionCache) Set(key string, value *utils.DialWrap) error {
	close(c.set)
	return c.Cache.Set(key, value)
}

func TestFailedWrapperEvictionSerializesWithPublication(t *testing.T) {
	base := gcache.New[string, *utils.DialWrap](4).Build()
	newWrap := func() *utils.DialWrap {
		w, err := utils.NewDialWrap(&net.Dialer{}, []string{"127.0.0.1"}, "tcp", "127.0.0.1:1", "1")
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	old, successor := newWrap(), newWrap()
	const key = "tcp-127.0.0.1:1"
	if err := base.Set(key, old); err != nil {
		t.Fatal(err)
	}
	paused := &pausedEvictionCache{Cache: base, readOld: make(chan struct{}), release: make(chan struct{}), set: make(chan struct{})}
	d := &Dialer{dialCache: paused}
	evicted := make(chan struct{})
	go func() { d.forgetFailedDialWrap(key, old); close(evicted) }()
	select {
	case <-paused.readOld:
	case <-time.After(5 * time.Second):
		t.Fatal("eviction never reached controlled read")
	}
	publishing := make(chan struct{})
	published := make(chan error, 1)
	go func() {
		close(publishing)
		published <- d.cacheDialWrap(key, successor) // same path as dial's Set
	}()
	<-publishing
	// If eviction or publication drops its lock, publication enters real Set
	// while Get still holds a captured old pointer. The final Remove then
	// demonstrably erases the successor. The wait also gives that faulty
	// publisher time to run; a timeout here is a success only with the lock held.
	var crossed bool
	select {
	case <-paused.set:
		crossed = true
	case <-time.After(100 * time.Millisecond):
	}
	close(paused.release)
	select {
	case <-evicted:
	case <-time.After(5 * time.Second):
		t.Fatal("eviction did not finish")
	}
	select {
	case err := <-published:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("publication did not finish")
	}
	if crossed {
		t.Error("publication crossed the captured-pointer/removal critical section")
	}
	if got, err := base.GetIFPresent(key); err != nil || got != successor {
		t.Errorf("check/remove race lost successor: got=%p err=%v", got, err)
	}
}
