package helper

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

// A mock for your "GetClient" function.
// If in your real code `GetClient` is in another file/package, you'll need
// to override it carefully or define an interface.
// For simplicity, we show an inline approach here.
var originalGetClient = helper.GetClient

func overrideGetClient(baseURL string) {
    // Create a fake function that returns an *appknox.Client pointing to our test server
    helper.GetClient = func() *appknox.Client {
        c, _ := appknox.NewClient("FAKE-TOKEN")
        c.BaseURL, _ = url.Parse(baseURL)
        return c
    }
}

func restoreGetClient() {
    helper.GetClient = originalGetClient
}

// captureOutput helps us capture what gets printed (fmt.Println, etc.) to stdout
func captureOutput(f func()) string {
    old := os.Stdout
    r, w, _ := os.Pipe()
    os.Stdout = w

    // Run the function while writing output to the pipe
    f()

    // Restore stdout, read from pipe
    _ = w.Close()
    os.Stdout = old
    var buf bytes.Buffer
    _, _ = io.Copy(&buf, r)
    return buf.String()
}

// TestRunDastCheck_NoScans demonstrates a scenario where dynamic_status=0
// and there are no historical scans => "No dynamic scan is running for the file."
func TestRunDastCheck_NoScans(t *testing.T) {
    // 1. Spin up a test server to mock the Appknox API
    //    It returns dynamic_status=0 and no scans for /api/v2/files/123/dynamicscans.
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        switch {
        case r.URL.Path == "/api/v2/files/123" && r.Method == http.MethodGet:
            // Mock "NONE" status
            fmt.Fprintf(w, `{"id":123,"dynamic_status":0}`)
        case r.URL.Path == "/api/v2/files/123/dynamicscans" && r.Method == http.MethodGet:
            // No scans in history
            fmt.Fprintf(w, `{"count":0,"results":[]}`)
        default:
            http.NotFound(w, r)
        }
    }))
    defer server.Close()

    // 2. Override GetClient so it points to our test server
    overrideGetClient(server.URL + "/") // note the trailing slash
    defer restoreGetClient()

    // 3. Run the code under test, capturing output
    output := captureOutput(func() {
        err := helper.RunDastCheck("123", 3)
        // We expect no error in this scenario
        assert.NoError(t, err)
    })

    // 4. Verify it printed "No dynamic scan is running for the file."
    assert.Contains(t, output, "No dynamic scan is running for the file.")
}

// TestRunDastCheck_InQueue demonstrates a scenario where dynamic_status=1 => “Status: inqueue”
func TestRunDastCheck_InQueue(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/api/v2/files/999" && r.Method == http.MethodGet {
            // Return dynamic_status=1
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

// TestRunDastCheck_CompletedNoVulns demonstrates scenario where dynamic_status != 0 or 1,
// so we check scans. The last scan is “analysis_completed(22)” => "Dynamic scan has completed successfully."
// Then we see no vulnerabilities above the threshold => "No dynamic vulnerabilities..."
func TestRunDastCheck_CompletedNoVulns(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        switch {
        case r.URL.Path == "/api/v2/files/777" && r.Method == http.MethodGet:
            // Return dynamic_status=9 or some code >1 => triggers "in progress" path
            fmt.Fprintf(w, `{"id":777,"dynamic_status":5}`)
        case r.URL.Path == "/api/v2/files/777/dynamicscans" && r.Method == http.MethodGet:
            // Return a single "completed" scan with status=22
            fmt.Fprintf(w, `{
                "count":1,
                "results":[
                  {"id":222,"status":22,"error_message":""}
                ]
            }`)
        case r.URL.Path == "/api/v2/files/777/analyses" && r.Method == http.MethodGet:
            // Return no vulnerabilities in results
            fmt.Fprintf(w, `{
                "count":0,
                "results":[]
            }`)
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

    // We expect:
    //   1) "Dynamic scan has completed successfully."
    //   2) "No dynamic vulnerabilities with risk >= 3."
    assert.Contains(t, output, "Dynamic scan has completed successfully.")
    assert.Contains(t, output, "No dynamic vulnerabilities with risk >= 3.")
}
