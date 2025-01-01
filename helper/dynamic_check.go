package helper

import (
    "context"
    "fmt"
    "net/http"

    "github.com/appknox/appknox-go/appknox"
)

// DynamicScan represents a single dynamic scan object.
type DynamicScan struct {
    ID           int    `json:"id"`
    Status       int    `json:"status"`
    ErrorMessage string `json:"error_message"`
    // Add other fields if needed (e.g., "file", "mode", "started_by_user", etc.)
}

// Analysis represents a single vulnerability.
type Analysis struct {
    ID    int    `json:"id"`
    Title string `json:"title"`
    Risk  int    `json:"risk"`
}

// GetFileDynamicStatus calls GET /api/v2/files/:file_id and returns the dynamic_status.
func GetFileDynamicStatus(client *appknox.Client, fileID string) (int, error) {
    endpoint := fmt.Sprintf("/api/v2/files/%s", fileID)

    req, err := client.NewRequest(http.MethodGet, endpoint, nil)
    if err != nil {
        return 0, err
    }

    var response struct {
        ID            int `json:"id"`
        DynamicStatus int `json:"dynamic_status"`
        // possibly many other fields, but we only care about dynamic_status here
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

// dynamicScansResponse matches the JSON structure for /api/v2/files/:file_id/dynamicscans,
// which typically looks like:
// {
//   "count": 1,
//   "next": null,
//   "previous": null,
//   "results": [ { ... }, ... ]
// }
type dynamicScansResponse struct {
    Count    int           `json:"count"`
    Next     *string       `json:"next"`
    Previous *string       `json:"previous"`
    Results  []DynamicScan `json:"results"`
}

// GetLatestDynamicScan calls GET /api/v2/files/:file_id/dynamicscans
// and returns the first (latest) dynamic scan (or nil if none).
func GetLatestDynamicScan(client *appknox.Client, fileID string) (*DynamicScan, error) {
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

    // If there are no scans, return nil.
    if len(dsResp.Results) == 0 {
        return nil, nil
    }

    // Return the first (most recent) dynamic scan.
    return &dsResp.Results[0], nil
}

// analysisResponse matches the JSON structure for /api/v2/files/:file_id/analyses?vulnerability_type=2,
// which typically looks like:
// {
//   "count": 2,
//   "next": null,
//   "previous": null,
//   "results": [
//       { "id": 123, "title": "..." , "risk": 4 },
//       { "id": 124, "title": "..." , "risk": 5 }
//   ]
// }
type analysisResponse struct {
    Count    int        `json:"count"`
    Next     *string    `json:"next"`
    Previous *string    `json:"previous"`
    Results  []Analysis `json:"results"`
}

// GetDynamicAnalyses calls GET /api/v2/files/:file_id/analyses?vulnerability_type=2
// to retrieve dynamic vulnerabilities.
func GetDynamicAnalyses(client *appknox.Client, fileID string) ([]Analysis, error) {
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

    // Return the parsed list of Analysis objects.
    return aResp.Results, nil
}
