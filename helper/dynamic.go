package helper

import (
    "context"
    "fmt"
    "net/http"

    "github.com/appknox/appknox-go/appknox"
)

// ScheduleDastAutomation calls the POST /api/dynamicscan/<file_id>/schedule_automation endpoint
func ScheduleDastAutomation(client *appknox.Client, fileID string) error {
    endpoint := fmt.Sprintf("/api/dynamicscan/%s/schedule_automation", fileID)

    req, err := client.NewRequest(http.MethodPost, endpoint, nil)
    if err != nil {
        return fmt.Errorf("failed to create request: %w", err)
    }

    // Use context.Background() or any other context you have
    resp, err := client.Do(context.Background(), req, nil)
    if err != nil {
        return fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()

    switch resp.StatusCode {
    case 204:
        // Success
        return nil
    case 400:
        return fmt.Errorf("dynamic scan automation is not enabled")
    case 403:
        return fmt.Errorf("there is a dynamic scan in progress, cannot schedule automation at the moment")
    default:
        return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
    }
}
