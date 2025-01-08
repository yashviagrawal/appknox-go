package helper

import (
    "context"
    "fmt"
    "net/http"

    //"github.com/appknox/appknox-go/appknox"
)

// ScheduleDastAutomation obtains a client, then POSTs to schedule the dynamic scan.
// It returns nil on success (204), or an error if there's a known/unknown problem.
func ScheduleDastAutomation(fileID string) error {
    // 1. Get your client — either an exported or unexported function from clientinitialize.go
    client := GetClient() // or GetClient() if exported

    // 2. Build the request
    endpoint := fmt.Sprintf("/api/dynamicscan/%s/schedule_automation", fileID)
    req, err := client.NewRequest(http.MethodPost, endpoint, nil)
    if err != nil {
        return fmt.Errorf("failed to create request: %w", err)
    }

    // 3. Perform the request
    resp, err := client.Do(context.Background(), req, nil)
    if err != nil {
        return fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()

    // 4. Handle the various known status codes
    switch resp.StatusCode {
    case 204:
        // success => scanning inqueued
        return nil
    case 400:
        return fmt.Errorf("dynamic scan automation is not enabled")
    case 403:
        return fmt.Errorf("there is a dynamic scan in progress, cannot schedule automation at the moment")
    default:
        return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
    }
}
