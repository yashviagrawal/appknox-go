package helper_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/appknox/appknox-go/appknox"
	"github.com/appknox/appknox-go/helper"
	"github.com/stretchr/testify/assert"
)

var originalGetClient = helper.GetClient

func overrideGetClient(baseURL string) {
	helper.GetClient = func() *appknox.Client {
		c, _ := appknox.NewClient("FAKE-TOKEN")
		c.BaseURL, _ = url.Parse(baseURL)
		return c
	}
}

func restoreGetClient() {
	helper.GetClient = originalGetClient
}

func captureOutput(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func TestRunDastCheckNoScans(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v2/files/123" && r.Method == http.MethodGet:
			fmt.Fprintf(w, `{"id":123,"dynamic_status":0}`)
		case r.URL.Path == "/api/v2/files/123/dynamicscans" && r.Method == http.MethodGet:
			fmt.Fprintf(w, `{"count":0,"results":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	overrideGetClient(server.URL + "/")
	defer restoreGetClient()

	output := captureOutput(func() {
		err := helper.RunDastCheck("123", 3)
		assert.NoError(t, err)
	})

	assert.Contains(t, output, "No dynamic scan is running for the file.")
}

func TestRunDastCheckInQueue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/files/999" && r.Method == http.MethodGet {
			fmt.Fprintf(w, `{"id":999,"dynamic_status":1}`)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	overrideGetClient(server.URL + "/")
	defer restoreGetClient()

	output := captureOutput(func() {
		err := helper.RunDastCheck("999", 3)
		assert.NoError(t, err)
	})
	assert.Contains(t, output, "Status: inqueue")
}

func TestRunDastCheckCompletedNoVulns(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v2/files/777" && r.Method == http.MethodGet:
			fmt.Fprintf(w, `{"id":777,"dynamic_status":5}`)
		case r.URL.Path == "/api/v2/files/777/dynamicscans" && r.Method == http.MethodGet:
			fmt.Fprintf(w, `{
				"count":1,
				"results":[{"id":222,"status":22,"error_message":""}]
			}`)
		case r.URL.Path == "/api/v2/files/777/analyses" && r.Method == http.MethodGet:
			fmt.Fprintf(w, `{"count":0,"results":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	overrideGetClient(server.URL + "/")
	defer restoreGetClient()

	output := captureOutput(func() {
		err := helper.RunDastCheck("777", 3)
		assert.NoError(t, err)
	})

	assert.Contains(t, output, "Dynamic scan has completed successfully.")
	assert.Contains(t, output, "No dynamic vulnerabilities with risk >= 3.")
}
