package helper

import (
    "context"
    "fmt"
    "net/http"
    "time"

    "github.com/appknox/appknox-go/appknox"
)

// ------------------------- Structures -------------------------

// DynamicScan represents a single dynamic scan object.
type DynamicScan struct {
    ID           int    `json:"id"`
    Status       int    `json:"status"`
    ErrorMessage string `json:"error_message"`
    // Add other fields if needed (e.g., file, mode, started_by_user, etc.)
}

// Analysis represents a single vulnerability.
type Analysis struct {
    ID    int    `json:"id"`
    Title string `json:"title"`
    Risk  int    `json:"risk"`
}

// dynamicScansResponse matches JSON from /api/v2/files/:file_id/dynamicscans
type dynamicScansResponse struct {
    Count    int           `json:"count"`
    Next     *string       `json:"next"`
    Previous *string       `json:"previous"`
    Results  []DynamicScan `json:"results"`
}

// analysisResponse matches JSON from /api/v2/files/:file_id/analyses?vulnerability_type=2
type analysisResponse struct {
    Count    int        `json:"count"`
    Next     *string    `json:"next"`
    Previous *string    `json:"previous"`
    Results  []Analysis `json:"results"`
}

// ----------------------- Public Entry Point -----------------------

// RunDastCheck is the single entry point that the `dastcheck` CLI command calls.
// It obtains the client from clientinitialize.go, checks dynamic_status, then
// either prints "in queue" or calls `handleDynamicScan` for further logic.
func RunDastCheck(fileID string, riskThreshold int) error {
    // 1. Obtain the client from your clientinitialize.go (use your actual function name)
    client := GetClient()

    // 2. Check the file's dynamic_status (0=NONE, 1=INQUEUE, others=>in-progress)
    dynamicStatus, err := getFileDynamicStatus(client, fileID)
    if err != nil {
        return err
    }

    // 3. Decide scenario
    switch dynamicStatus {
    case 1:
        // INQUEUE
        fmt.Println("Status: inqueue")
        return nil

    default:
        // For 0 (NONE) or anything else (2..9):
        // unify logic by calling `handleDynamicScan`
        return handleDynamicScan(client, fileID, riskThreshold)
    }
}

// ------------------------ Internal Helpers ------------------------

// getFileDynamicStatus calls GET /api/v2/files/:file_id and returns dynamic_status
func getFileDynamicStatus(client *appknox.Client, fileID string) (int, error) {
    endpoint := fmt.Sprintf("/api/v2/files/%s", fileID)

    req, err := client.NewRequest(http.MethodGet, endpoint, nil)
    if err != nil {
        return 0, err
    }

    var response struct {
        ID            int `json:"id"`
        DynamicStatus int `json:"dynamic_status"`
    }

    resp, err := client.Do(context.Background(), req, &response)
    if err != nil {
        return 0, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
    }

    return response.DynamicStatus, nil
}


// 1) Get the latest dynamic scan
// 2) If none => print "No dynamic scan" and return
// 3) If status=22 => "completed", show vulnerabilities
// 4) If status=23/24/25 => "ended" + error
// 5) Otherwise => poll
func handleDynamicScan(client *appknox.Client, fileID string, riskThreshold int) error {
    scanInfo, err := getLatestDynamicScan(client, fileID)
    if err != nil {
        return err
    }

    // If no scan found at all
    if scanInfo == nil {
        fmt.Println("No dynamic scan is running for the file.")
        return nil
    }

    // Now check the status
    switch scanInfo.Status {
    case 22:
        // ANALYSIS_COMPLETED
        fmt.Println("Dynamic scan has completed successfully.")
        return showDynamicVulnerabilities(client, fileID, riskThreshold)

    case 23, 24, 25:
        // TIMED_OUT, ERROR, CANCELLED
        fmt.Printf("Dynamic scan ended with status %d\n", scanInfo.Status)
        if scanInfo.ErrorMessage != "" {
            fmt.Printf("Error message: %s\n", scanInfo.ErrorMessage)
        }
        return nil

    default:
        // in progress => poll until finished
        fmt.Printf("Dynamic scan is in progress (status=%d). Polling...\n", scanInfo.Status)
        return pollUntilFinished(client, fileID, scanInfo, riskThreshold)
    }
}

// pollUntilFinished polls /api/v2/files/:file_id/dynamicscans every 60s
// until the scan is in a terminating state (22/23/24/25) or no scan is found.
func pollUntilFinished(client *appknox.Client, fileID string, initialScan *DynamicScan, riskThreshold int) error {
    currentStatus := initialScan.Status

    for {
        time.Sleep(60 * time.Second)

        scanInfo, err := getLatestDynamicScan(client, fileID)
        if err != nil {
            return err
        }

        if scanInfo == nil {
            fmt.Println("No dynamic scan is running for the file.")
            return nil
        }

        // If status changed, print the change
        if scanInfo.Status != currentStatus {
            fmt.Printf("Status changed from %d to %d\n", currentStatus, scanInfo.Status)
            currentStatus = scanInfo.Status
        }

        switch scanInfo.Status {
        case 22:
            fmt.Println("Dynamic scan has completed successfully.")
            return showDynamicVulnerabilities(client, fileID, riskThreshold)

        case 23, 24, 25:
            fmt.Printf("Dynamic scan ended with status %d\n", scanInfo.Status)
            if scanInfo.ErrorMessage != "" {
                fmt.Printf("Error message: %s\n", scanInfo.ErrorMessage)
            }
            return nil

        default:
            fmt.Printf("Dynamic scan is still in progress (status=%d)\n", scanInfo.Status)
        }
    }
}

// getLatestDynamicScan calls GET /api/v2/files/:file_id/dynamicscans
func getLatestDynamicScan(client *appknox.Client, fileID string) (*DynamicScan, error) {
    endpoint := fmt.Sprintf("/api/v2/files/%s/dynamicscans", fileID)

    req, err := client.NewRequest(http.MethodGet, endpoint, nil)
    if err != nil {
        return nil, err
    }

    var dsResp dynamicScansResponse
    resp, err := client.Do(context.Background(), req, &dsResp)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
    }

    if len(dsResp.Results) == 0 {
        return nil, nil
    }
    return &dsResp.Results[0], nil
}

// showDynamicVulnerabilities fetches and filters dynamic vulnerabilities
func showDynamicVulnerabilities(client *appknox.Client, fileID string, riskThreshold int) error {
    analyses, err := getDynamicAnalyses(client, fileID)
    if err != nil {
        return err
    }

    filtered := make([]Analysis, 0, len(analyses))
    for _, a := range analyses {
        if a.Risk >= riskThreshold {
            filtered = append(filtered, a)
        }
    }

    if len(filtered) == 0 {
        fmt.Printf("No dynamic vulnerabilities with risk >= %d.\n", riskThreshold)
        return nil
    }

    fmt.Println("Dynamic Vulnerabilities Found:")
    for _, fa := range filtered {
        fmt.Printf("- [%d] %s (Risk=%d)\n", fa.ID, fa.Title, fa.Risk)
    }
    return nil
}

// getDynamicAnalyses calls GET /api/v2/files/:file_id/analyses?vulnerability_type=2
func getDynamicAnalyses(client *appknox.Client, fileID string) ([]Analysis, error) {
    endpoint := fmt.Sprintf("/api/v2/files/%s/analyses?vulnerability_type=2", fileID)

    req, err := client.NewRequest(http.MethodGet, endpoint, nil)
    if err != nil {
        return nil, err
    }

    var aResp analysisResponse
    resp, err := client.Do(context.Background(), req, &aResp)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
    }

    return aResp.Results, nil
}
