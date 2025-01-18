package helper

import (
    "context"
    "fmt"
    "os"
    "time"

    "github.com/appknox/appknox-go/appknox"
    // We'll import both "DynamicScanState" and "DynamicScanStatus"
    "github.com/appknox/appknox-go/appknox/enums"
    "github.com/cheynewallace/tabby"
)

// ----------------------- Public Entry Point -----------------------
//
// RunDastCheck is the single entry point that the `dastcheck` CLI command calls.
// 1) We get the file-level dynamic_status (0=none, 1=in-queue, etc.) from dynamicScanState.go
// 2) If it's none or in-queue, we handle it right away.
// 3) Otherwise, we proceed to check the deeper dynamic scan statuses (22=AnalysisCompleted, etc.)
func RunDastCheck(fileID int, riskThreshold int) error {
    client := getClient()

    file, _, err := client.Files.GetByID(context.Background(), fileID)
    if err != nil {
        PrintError(err)
        os.Exit(1)
        return err
    }

    // Compare file.DynamicStatus to dynamicScanState.go
    // e.g. 0 => None, 1 => InQueue
    switch file.DynamicStatus {
    case enums.DynamicScanState.InQueue:
        // e.g. in-queue => "Status: inqueue" then stop
        fmt.Println("Status: inqueue")
        return nil

    case enums.DynamicScanState.None:
        // If you want special logic for "NONE=0" here, you can handle it,
        // e.g., "No dynamic scan is running for the file." and return
        // or do nothing and fall through to deeper logic if you want.
        fmt.Println("No dynamic scan is running for the file.")
        return nil

    default:
        // If it's not in-queue or none, we proceed to see what's happening at the deeper dynamicScan level
        return handleDynamicScan(client, fileID, riskThreshold)
    }
}

// ------------------------ Internal Helpers ------------------------
//
// handleDynamicScan does the deeper logic:
// 1) We fetch the latest dynamic scan object => dynamicScan.Status
// 2) dynamicScan.Status references dynamicScanStatus.go (22=AnalysisCompleted, 23=TimedOut, etc.)
// 3) Switch on those values to handle finishing states vs. in-progress
func handleDynamicScan(client *appknox.Client, fileID int, riskThreshold int) error {
    // We'll wait up to 60 minutes before concluding a "timeout"
    timeOut := 60 * time.Minute

    dynamicScan, err := getFinishedDynamicScan(client, fileID, timeOut)
    if err != nil {
        PrintError(err)
        os.Exit(1)
        return err
    }

    // If there's no historical scan at all
    if dynamicScan == nil {
        fmt.Println("No dynamic scan is running for the file.")
        return nil
    }

    // Now check the dynamicScan.Status using dynamicScanStatus.go
    // (22 => AnalysisCompleted, 23 => TimedOut, 24 => Error, 25 => Cancelled, etc.)
    switch dynamicScan.Status {
    case enums.DynamicScanStatus.AnalysisCompleted:
        fmt.Println("Dynamic scan has completed successfully.")
        return showDynamicVulnerabilities(client, fileID, riskThreshold)

    case enums.DynamicScanStatus.TimedOut,
        enums.DynamicScanStatus.Error,
        enums.DynamicScanStatus.Cancelled:
        // e.g. 23 => TimedOut, 24 => Error, 25 => Cancelled
        fmt.Printf("Dynamic scan ended with status %d\n", dynamicScan.Status)
        if dynamicScan.ErrorMessage != "" {
            fmt.Printf("Error message: %s\n", dynamicScan.ErrorMessage)
        }
        return nil

    default:
        // If none of the above, we say "Request timed out" or "still in progress"
        // Up to you. This example says "timed out" for any unrecognized status.
        fmt.Printf("Request timed out for file ID %d\n", fileID)
        return nil
    }
}

// getFinishedDynamicScan polls /api/v2/files/:file_id/dynamicscans every 60s
// until we see dynamicScan.Status in a "terminating" state like 22(AnalysisCompleted),
// 23(TimedOut), 24(Error), 25(Cancelled), or we run out of time (60 min).
func getFinishedDynamicScan(client *appknox.Client, fileID int, timeOut time.Duration) (*appknox.DynamicScan, error) {
    startTime := time.Now()
    for {
        dynamicScan, err := getLatestDynamicScan(client, fileID)
        if err != nil {
            PrintError(err)
            os.Exit(1)
            return nil, err
        }
        if dynamicScan == nil {
            // no scans exist
            return nil, nil
        }

        // Check if dynamicScan.Status is one of 22,23,24,25
        switch dynamicScan.Status {
        case enums.DynamicScanStatus.AnalysisCompleted,
            enums.DynamicScanStatus.TimedOut,
            enums.DynamicScanStatus.Error,
            enums.DynamicScanStatus.Cancelled:
            return dynamicScan, nil

        default:
            // if it's not one of those, we keep waiting
            fmt.Printf("Dynamic scan is still in progress (status=%d)\n", dynamicScan.Status)
        }

        if time.Since(startTime) > timeOut {
            return dynamicScan, nil
        }
        time.Sleep(1 * time.Minute)
    }
}

// getLatestDynamicScan calls GET /api/v2/files/:file_id/dynamicscans to see the last dynamic scan
func getLatestDynamicScan(client *appknox.Client, fileID int) (*appknox.DynamicScan, error) {
    dynamicScans, _, err := client.DynamicScans.ListByFile(context.Background(), fileID)
    if err != nil {
        PrintError(err)
        os.Exit(1)
        return nil, err
    }

    if len(dynamicScans) == 0 {
        return nil, nil
    }
    return dynamicScans[0], nil
}

// showDynamicVulnerabilities fetches and filters vulnerabilities from GET /api/v2/files/:file_id/analyses
func showDynamicVulnerabilities(client *appknox.Client, fileID int, riskThreshold int) error {
    analyses, err := getDynamicAnalyses(client, fileID)
    if err != nil {
        PrintError(err)
        os.Exit(1)
        return err
    }

    var filteredAnalysis []appknox.Analysis
    for _, a := range analyses {
        if int(a.ComputedRisk) >= riskThreshold {
            filteredAnalysis = append(filteredAnalysis, *a)
        }
    }

    if len(filteredAnalysis) == 0 {
        fmt.Printf("\nNo vulnerabilities found with risk threshold >= %s\n", enums.RiskType(riskThreshold))
        fmt.Printf("\nCheck file ID %d on Appknox dashboard for more details.\n", fileID)
        return nil
    }

    fmt.Printf("Found %d vulnerabilities with risk >= %s\n", len(filteredAnalysis), enums.RiskType(riskThreshold))

    t := tabby.New()
    t.AddHeader(
        "ANALYSIS-ID",
        "RISK",
        "CVSS-VECTOR",
        "CVSS-BASE",
        "VULNERABILITY-ID",
        "VULNERABILITY-NAME",
    )
    for _, analysis := range filteredAnalysis {
        vulnerability, _, err := client.Vulnerabilities.GetByID(context.Background(), analysis.VulnerabilityID)
        if err != nil {
            PrintError(err)
            os.Exit(1)
            return err
        }
        t.AddLine(
            analysis.ID,
            analysis.ComputedRisk,
            analysis.CvssVector,
            analysis.CvssBase,
            analysis.VulnerabilityID,
            vulnerability.Name,
        )
    }

    t.Print()
    return nil
}

// getDynamicAnalyses calls GET /api/v2/files/:file_id/analyses?vulnerability_type=2
func getDynamicAnalyses(client *appknox.Client, fileID int) ([]*appknox.Analysis, error) {
    ctx := context.Background()
    options := &appknox.AnalysisListOptions{
        VulnerabilityType: 2,
    }
    _, dynamicAnalysesResponse, err := client.Analyses.ListByFile(ctx, fileID, options)
    if err != nil {
        PrintError(err)
        os.Exit(1)
        return nil, err
    }

    analysisCount := dynamicAnalysesResponse.GetCount()
    options.ListOptions = appknox.ListOptions{
        Limit: analysisCount,
    }
    dynamicAnalyses, _, err := client.Analyses.ListByFile(ctx, fileID, options)
    if err != nil {
        PrintError(err)
        os.Exit(1)
        return nil, err
    }
    return dynamicAnalyses, nil
}
