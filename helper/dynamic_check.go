package helper

import (
    "context"
    "fmt"
    "os"
    "time"

    "github.com/appknox/appknox-go/appknox"
    "github.com/appknox/appknox-go/appknox/enums"
    "github.com/cheynewallace/tabby"
)

// ----------------------- Public Entry Point -----------------------
//
// RunDastCheck is the single entry point that the `dastcheck` CLI command calls.
// It obtains the client from clientinitialize.go, checks dynamic_status, then
// either prints "in queue" or calls `handleDynamicScan` for further logic.
func RunDastCheck(fileID int, riskThreshold int) error {
    client := getClient()

    file, _, err := client.Files.GetByID(context.Background(), fileID)
    if err != nil {
        PrintError(err)
        os.Exit(1)
        return err
    }

    // Compare file.DynamicStatus to the enum for "InQueue"
    switch file.DynamicStatus {
    case enums.DynamicScanStatus.InQueue:
        fmt.Println("Status: inqueue")
        return nil
    default:
        // For anything else, handle dynamic scan flow
        return handleDynamicScan(client, fileID, riskThreshold)
    }
}

// ------------------------ Internal Helpers ------------------------
//
// 1) Get the latest dynamic scan
// 2) If none => print "No dynamic scan" and return
// 3) If status=AnalysisCompleted => "completed", show vulnerabilities
// 4) If status=TimedOut/Error/Cancelled => "ended" + error
// 5) Otherwise => poll
func handleDynamicScan(client *appknox.Client, fileID int, riskThreshold int) error {
    // Increase the timeout to 60 minutes
    timeOut := 60 * time.Minute
    dynamicScan, err := getFinishedDynamicScan(client, fileID, timeOut)
    if err != nil {
        PrintError(err)
        os.Exit(1)
        return err
    }

    // No scan at all
    if dynamicScan == nil {
        fmt.Println("No dynamic scan is running for the file.")
        return nil
    }

    // Check the dynamic scan status using the enum constants
    switch dynamicScan.Status {
    case enums.DynamicScanStatus.AnalysisCompleted:
        fmt.Println("Dynamic scan has completed successfully.")
        return showDynamicVulnerabilities(client, fileID, riskThreshold)
    case enums.DynamicScanStatus.TimedOut,
        enums.DynamicScanStatus.Error,
        enums.DynamicScanStatus.Cancelled:
        // TIMED_OUT(23), ERROR(24), CANCELLED(25)
        fmt.Printf("Dynamic scan ended with status %d\n", dynamicScan.Status)
        if dynamicScan.ErrorMessage != "" {
            fmt.Printf("Error message: %s\n", dynamicScan.ErrorMessage)
        }
        return nil
    default:
        fmt.Printf("Request timed out for file ID %d\n", fileID)
        return nil
    }
}

// pollUntilFinished polls /api/v2/files/:file_id/dynamicscans every 60s
// until the scan is in a terminating state (AnalysisCompleted, TimedOut, Error, Cancelled)
// or no scan is found.
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
            return nil, nil
        }

        switch dynamicScan.Status {
        case enums.DynamicScanStatus.AnalysisCompleted,
            enums.DynamicScanStatus.TimedOut,
            enums.DynamicScanStatus.Error,
            enums.DynamicScanStatus.Cancelled:
            return dynamicScan, nil
        default:
            fmt.Printf("Dynamic scan is still in progress (status=%s)\n", dynamicScan.Status)
        }

        if time.Since(startTime) > timeOut {
            return dynamicScan, nil
        }

        time.Sleep(1 * time.Minute)
    }
}

// getLatestDynamicScan calls GET /api/v2/files/:file_id/dynamicscans
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

// showDynamicVulnerabilities fetches and filters dynamic vulnerabilities
func showDynamicVulnerabilities(client *appknox.Client, fileID int, riskThreshold int) error {
    analyses, err := getDynamicAnalyses(client, fileID)
    if err != nil {
        PrintError(err)
        os.Exit(1)
        return err
    }

    filteredAnalysis := make([]appknox.Analysis, 0)
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
        vulnerability, _, err := client.Vulnerabilities.GetByID(
            context.Background(), analysis.VulnerabilityID,
        )
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
