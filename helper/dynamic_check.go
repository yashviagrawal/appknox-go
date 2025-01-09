package helper

import (
    "context"
    "fmt"
    "net/http"
    "time"

    "github.com/appknox/appknox-go/appknox"
    "github.com/cheynewallace/tabby"
)

// ------------------------- Structures -------------------------

type DynamicScan struct {
    ID           int    `json:"id"`
    Status       int    `json:"status"`
    ErrorMessage string `json:"error_message"`
}

type Analysis struct {
    ID                int    `json:"id"`
    Title             string `json:"title"`
    Risk              int    `json:"risk"`
    CvssVector        string `json:"cvss_vector"`
    CvssBase 		  float64 `json:"cvss_base"`
    VulnerabilityID   int    `json:"vulnerability_id"`
    VulnerabilityName string `json:"vulnerability_name"`
}

type dynamicScansResponse struct {
    Count    int           `json:"count"`
    Next     *string       `json:"next"`
    Previous *string       `json:"previous"`
    Results  []DynamicScan `json:"results"`
}

type analysisResponse struct {
    Count    int        `json:"count"`
    Next     *string    `json:"next"`
    Previous *string    `json:"previous"`
    Results  []Analysis `json:"results"`
}

// ----------------------- Public Entry Point -----------------------

func RunDastCheck(fileID string, riskThreshold int) error {
    client := getClient()

    dynamicStatus, err := getFileDynamicStatus(client, fileID)
    if err != nil {
        return err
    }

    switch dynamicStatus {
    case 1:
        fmt.Println("Status: inqueue")
        return nil
    default:
        return handleDynamicScan(client, fileID, riskThreshold)
    }
}

// ------------------------ Internal Helpers ------------------------

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

func handleDynamicScan(client *appknox.Client, fileID string, riskThreshold int) error {
    timeOut := 60 * time.Minute
    scanInfo, err := getFinishedDynamicScan(client, fileID, timeOut)
    if err != nil {
        return err
    }

    if scanInfo == nil {
        fmt.Println("No dynamic scan is running for the file.")
        return nil
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
        fmt.Printf("Request timed out for file ID %s\n", fileID)
        return nil
    }
}

// Poll until we reach a terminal state or time out
func getFinishedDynamicScan(client *appknox.Client, fileID string, timeOut time.Duration) (*DynamicScan, error) {
    startTime := time.Now()
    for {
        scanInfo, err := getLatestDynamicScan(client, fileID)
        if err != nil {
            return nil, err
        }
        if scanInfo == nil {
            return nil, nil
        }

        switch scanInfo.Status {
        case 22, 23, 24, 25:
            return scanInfo, nil
        default:
            fmt.Printf("Dynamic scan is still in progress (status=%d)\n", scanInfo.Status)
        }

        if time.Since(startTime) > timeOut {
            return scanInfo, nil
        }
        time.Sleep(1 * time.Minute)
    }
}

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
        fmt.Printf("\nNo vulnerabilities found with risk threshold >= %d\n", riskThreshold)
        fmt.Printf("\nCheck file ID %s on Appknox dashboard for more details.\n", fileID)
        return nil
    }

    fmt.Printf("Found %d vulnerabilities with risk >= %d\n", len(filtered), riskThreshold)

    t := tabby.New()
    t.AddHeader(
        "ANALYSIS-ID",
        "RISK",
        "CVSS-VECTOR",
        "CVSS-BASE",
        "VULNERABILITY-ID",
        "VULNERABILITY-NAME",
    )

    for _, analysis := range filtered {
        t.AddLine(
            analysis.ID,
            analysis.Risk,
            analysis.CvssVector,
            analysis.CvssBase,
            analysis.VulnerabilityID,
            analysis.VulnerabilityName,
        )
    }

    t.Print()
    fmt.Printf("\nCheck file ID %s on Appknox dashboard for more details.\n", fileID)

    return nil
}

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
