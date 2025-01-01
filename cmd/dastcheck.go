package cmd

import (
    "fmt"
    "time"

    // Bring in Cobra
    "github.com/spf13/cobra"

    // Bring in the actual "appknox.Client" definition
    "github.com/appknox/appknox-go/appknox"
    // Bring in the helper that has your GetFileDynamicStatus, GetLatestDynamicScan, etc.
    "github.com/appknox/appknox-go/helper"
)

var (
    riskThreshold int
)

// dastCheckCmd represents the "dastcheck" command
var dastCheckCmd = &cobra.Command{
    Use:   "dastcheck <file_id>",
    Short: "Check the status of a DAST scan for the specified file",
    Long: `Check the dynamic scan status for the specified file in Appknox.
If the scan is still in progress, this command will poll every 60 seconds.
Once the scan completes or fails, it will display the results or errors.
You can also filter vulnerabilities by using --risk-threshold <int>.`,
    Args: cobra.ExactArgs(1), // Exactly 1 arg: file_id
    RunE: func(cmd *cobra.Command, args []string) error {
        fileID := args[0]

        // 1. Call the helper logic
        err := handleDastCheck(fileID, riskThreshold)
        if err != nil {
            // Cobra prints "Error: <err>" if we return an error.
            return fmt.Errorf("dastcheck command failed: %v", err)
        }
        return nil
    },
}

func init() {
    // Assuming your root.go defines `var RootCmd = &cobra.Command{...}`
    RootCmd.AddCommand(dastCheckCmd)

    // Add the risk-threshold flag
    dastCheckCmd.Flags().IntVar(
        &riskThreshold,
        "risk-threshold",
        0, // default value
        "Filter vulnerabilities by minimum risk level (e.g. 1,2,3...). 0 = show all.",
    )
}

// handleDastCheck is the "business logic" function invoked by dastCheckCmd
func handleDastCheck(fileID string, riskThreshold int) error {
    client := helper.GetClient() // must return *appknox.Client

    // 1. Hit GET /api/v2/files/:file_id to fetch dynamic_status
    dynamicStatus, err := helper.GetFileDynamicStatus(client, fileID)
    if err != nil {
        return err
    }

    // Decide what to do based on dynamic_status
    switch dynamicStatus {
    case 1:
        // Scenario 1: INQUEUE
        fmt.Println("Status: inqueue")
        return nil

    case 0:
        // Scenario 3: NONE => We check the dynamic scans endpoint
        err = handleDynamicStatusNone(client, fileID, riskThreshold)
        return err

    default:
        // Scenario 2: dynamic_status not INQUEUE(1) or NONE(0)
        // => means the scan is in progress, or possibly completed. Let's check deeper.
        err = handleDynamicStatusInProgress(client, fileID, riskThreshold)
        return err
    }
}

// handleDynamicStatusNone deals with dynamic_status == 0
func handleDynamicStatusNone(client *appknox.Client, fileID string, riskThreshold int) error {
    scanInfo, err := helper.GetLatestDynamicScan(client, fileID)
    if err != nil {
        return err
    }

    if scanInfo == nil {
        // Means GET /api/v2/files/:file_id/dynamicscans returned zero results
        fmt.Println("No dynamic scan is running for the file.")
        return nil
    }

    // If we have a scan but dynamic_status=0 in the file details,
    // it might be in a final or mid-processing state
    switch scanInfo.Status {
    case 23, 24, 25:
        // TIMED_OUT(23), ERROR(24), CANCELLED(25)
        fmt.Printf("Dynamic scan ended with status %d\n", scanInfo.Status)
        if scanInfo.ErrorMessage != "" {
            fmt.Printf("Error message: %s\n", scanInfo.ErrorMessage)
        }
        return nil

    case 22:
        // ANALYSIS_COMPLETED(22) => success
        fmt.Println("Dynamic scan has completed successfully.")
        return showDynamicVulnerabilities(client, fileID, riskThreshold)

    default:
        // It's in some intermediate state, so we poll until it’s in a terminating state
        fmt.Printf("Dynamic scan is in progress (status=%d). Polling...\n", scanInfo.Status)
        return pollUntilFinished(client, fileID, scanInfo, riskThreshold)
    }
}

// handleDynamicStatusInProgress deals with scenario 2 (dynamic_status != 0 or 1)
func handleDynamicStatusInProgress(client *appknox.Client, fileID string, riskThreshold int) error {
    scanInfo, err := helper.GetLatestDynamicScan(client, fileID)
    if err != nil {
        return err
    }
    if scanInfo == nil {
        // Odd scenario: dynamic_status != 0 or 1 but no scans
        fmt.Println("No dynamic scan is currently running.")
        return nil
    }

    switch scanInfo.Status {
    // TERMINATING STATES
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
        // In-progress
        fmt.Printf("Dynamic scan is in progress (status=%d). Polling...\n", scanInfo.Status)
        return pollUntilFinished(client, fileID, scanInfo, riskThreshold)
    }
}

// pollUntilFinished polls the /api/v2/files/:file_id/dynamicscans endpoint every 60s
func pollUntilFinished(client *appknox.Client, fileID string, initialScan *helper.DynamicScan, riskThreshold int) error {
    currentStatus := initialScan.Status

    for {
        // Sleep 60 seconds
        time.Sleep(60 * time.Second)

        // Re-fetch the latest dynamic scan info
        scanInfo, err := helper.GetLatestDynamicScan(client, fileID)
        if err != nil {
            return err
        }
        if scanInfo == nil {
            fmt.Println("No dynamic scan is running for the file.")
            return nil
        }

        // If the status changed, print the new status
        if scanInfo.Status != currentStatus {
            fmt.Printf("Status changed from %d to %d\n", currentStatus, scanInfo.Status)
            currentStatus = scanInfo.Status
        }

        // Check if we’re in a terminating state
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
            // Still in progress
            fmt.Printf("Dynamic scan is still in progress (status=%d)\n", scanInfo.Status)
        }
    }
}

// showDynamicVulnerabilities fetches and filters dynamic vulnerabilities
func showDynamicVulnerabilities(client *appknox.Client, fileID string, riskThreshold int) error {
    analyses, err := helper.GetDynamicAnalyses(client, fileID)
    if err != nil {
        return err
    }

    // Filter analyses by risk threshold
    filtered := make([]helper.Analysis, 0, len(analyses))
    for _, analysis := range analyses {
        if analysis.Risk >= riskThreshold {
            filtered = append(filtered, analysis)
        }
    }

    if len(filtered) == 0 {
        fmt.Printf("No dynamic vulnerabilities with risk >= %d.\n", riskThreshold)
        return nil
    }

    // Print the vulnerabilities in the same style as "cicheck"
    fmt.Println("Dynamic Vulnerabilities Found:")
    for _, fa := range filtered {
        fmt.Printf("- [%d] %s (Risk=%d)\n", fa.ID, fa.Title, fa.Risk)
    }
    return nil
}
