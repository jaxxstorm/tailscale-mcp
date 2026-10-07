//go:build unix

package workloadidentity

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestKubernetesRejectsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := Acquire(context.Background(), Config{Provider: "kubernetes", Audience: "test", TokenFile: path})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accepted FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked opening FIFO")
	}
}
