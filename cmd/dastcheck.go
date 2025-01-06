package cmd

import (
    "fmt"

    "github.com/spf13/cobra"
    "github.com/appknox/appknox-go/helper"
)

// riskThreshold is set via the --risk-threshold flag
var riskThreshold int

// dastCheckCmd represents the "dastcheck" command
var dastCheckCmd = &cobra.Command{
    Use:   "dastcheck <file_id>",
    Short: "Check the status of a DAST scan for the specified file",
    Long: `Check the dynamic scan status for the specified file in Appknox.
If the scan is still in progress, this command will poll every 60 seconds.
Once the scan completes or fails, it will display the results or errors.
You can also filter vulnerabilities by using --risk-threshold <int>.`,
    Args: cobra.ExactArgs(1), // exactly 1 argument: file_id
    RunE: func(cmd *cobra.Command, args []string) error {
        fileID := args[0]

        // Call the single helper function that does everything
        if err := helper.RunDastCheck(fileID, riskThreshold); err != nil {
            return fmt.Errorf("dastcheck command failed: %v", err)
        }
        return nil
    },
}

func init() {
    // Assuming your root.go defines var RootCmd = &cobra.Command{...}
    RootCmd.AddCommand(dastCheckCmd)

    // Add the --risk-threshold flag
    dastCheckCmd.Flags().IntVar(
        &riskThreshold,
        "risk-threshold",
        0, // default
        "Filter vulnerabilities by minimum risk level (e.g. 1,2,3...). 0 = show all.",
    )
}
