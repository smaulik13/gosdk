package http

import (
	"net/http"
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

const (
	RetryWaitMax = 120 * time.Second
	RetryMax     = 60
)

// NewClient creates default http.Client with timeouts.
func NewClient() *http.Client {
	return &http.Client{
		Transport: http.DefaultTransport,
	}
}

func CleanClient() *http.Client {
	client := &http.Client{
		Transport: http.DefaultTransport,
	}
	client.Timeout = 250 * time.Second
	return client
}

// NewRetryableClient creates default retryablehttp.Client with timeouts and embedded NewClient result.
func NewRetryableClient(verbose bool) *retryablehttp.Client {
	client := retryablehttp.NewClient()
	client.HTTPClient = &http.Client{
		Transport: http.DefaultTransport,
	}

	if !verbose {
		client.Logger = nil
	}

	return client
}
