package workloadidentity

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type doFunc func(*http.Request) (*http.Response, error)

func (f doFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestAcquisitionClientContextAndBody(t *testing.T) {
	for _, mode := range []string{"close", "acquisition-cancel", "request-cancel", "shorter-sdk-deadline", "error"} {
		t.Run(mode, func(t *testing.T) {
			acquisition, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			request, cancelRequest := context.WithCancel(context.Background())
			defer cancelRequest()
			var sdkDeadline time.Time
			if mode == "shorter-sdk-deadline" {
				var stop context.CancelFunc
				request, stop = context.WithTimeout(request, 20*time.Millisecond)
				defer stop()
				sdkDeadline, _ = request.Deadline()
			}
			var bound context.Context
			body := &trackingBody{Reader: strings.NewReader("body")}
			client := acquisitionClient{ctx: acquisition, client: doFunc(func(r *http.Request) (*http.Response, error) {
				bound = r.Context()
				if mode == "error" {
					return nil, errors.New("failure")
				}
				return &http.Response{Body: body}, nil
			})}
			req, err := http.NewRequestWithContext(request, "GET", "http://offline.invalid", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if mode == "error" {
				if err == nil || bound.Err() == nil {
					t.Fatal("error did not release request context")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if mode == "shorter-sdk-deadline" {
				if got, _ := bound.Deadline(); !got.Equal(sdkDeadline) {
					t.Fatal("extended SDK deadline")
				}
			} else if bound.Err() != nil {
				t.Fatal("cancelled before response body consumption")
			}
			want := context.Canceled
			switch mode {
			case "close":
				if data, err := io.ReadAll(resp.Body); err != nil || string(data) != "body" {
					t.Fatalf("body unavailable: %v", err)
				}
				if err := resp.Body.Close(); err != nil {
					t.Fatal(err)
				}
				if !body.closed {
					t.Fatal("underlying body not closed")
				}
			case "acquisition-cancel":
				cancel()
			case "request-cancel":
				cancelRequest()
			case "shorter-sdk-deadline":
				want = context.DeadlineExceeded
			}
			select {
			case <-bound.Done():
				if !errors.Is(bound.Err(), want) {
					t.Fatalf("wrong context error: %v", bound.Err())
				}
			case <-time.After(time.Second):
				t.Fatal("request context remained active")
			}
		})
	}
}

type trackingBody struct {
	io.Reader
	closed bool
}

func (b *trackingBody) Close() error { b.closed = true; return nil }

func TestAcquisitionClientRejectsCancelledRequest(t *testing.T) {
	for _, cancelAcquisition := range []bool{false, true} {
		acquisition, cancel := context.WithCancel(context.Background())
		request, cancelRequest := context.WithCancel(context.Background())
		if cancelAcquisition {
			cancel()
		} else {
			cancelRequest()
		}
		body := &trackingBody{Reader: strings.NewReader("request")}
		req, err := http.NewRequestWithContext(request, "POST", "http://offline.invalid", body)
		if err != nil {
			t.Fatal(err)
		}
		client := acquisitionClient{ctx: acquisition, client: doFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("sent request after cancellation")
			return nil, nil
		})}
		if _, err := client.Do(req); !errors.Is(err, context.Canceled) {
			t.Fatalf("wrong error: %v", err)
		}
		if !body.closed {
			t.Fatal("rejected request body not closed")
		}
		cancel()
		cancelRequest()
	}
}
