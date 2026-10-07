package workloadidentity

import (
	"context"
	"errors"
	"os"
)

func readToken(ctx context.Context, path string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if path == "" {
		path = defaultTokenFile
	}
	// Check before opening to reject FIFOs without blocking, and again after
	// opening because kubelet can replace the symlink between these operations.
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("token file must be regular")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("token file must be regular")
	}
	if info.Size() > maxSize {
		return "", errors.New("token file exceeds 1 MiB")
	}
	b, err := readBounded(f)
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return string(b), err
}
