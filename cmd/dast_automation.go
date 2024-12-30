package cmd

import (
    "fmt"

    // Import your helper package that contains `GetClient()` and `ScheduleDastAutomation(...)`
    "github.com/appknox/appknox-go/helper"
    "github.com/spf13/cobra"
)

// scheduleDastAutomationCmd represents the schedule DAST automation command
var scheduleDastAutomationCmd = &cobra.Command{
    Use:   "schedule-dast-automation <file_id>",
    Short: "Schedule a DAST automation for the specified file",
    Long: `Send a request to schedule DAST automation for the specified file ID in Appknox.
This command calls POST /api/dynamicscan/<file_id>/schedule_automation to enqueue a dynamic scan.`,
    Args: cobra.ExactArgs(1),
    RunE: func(cmd *cobra.Command, args []string) error {
        fileID := args[0]

        // Print an informative message
        fmt.Printf("Scheduling DAST automation for file: %s\n", fileID)

        // 1. Initialize your API client
        client := helper.GetClient()

        // 2. Call the relevant helper function to schedule DAST
        err := helper.ScheduleDastAutomation(client, fileID)
        if err != nil {
            // Show error and exit
            return fmt.Errorf("failed to schedule DAST: %v", err)
        }

        // On success, just let the user know
        fmt.Println("Dynamic scan has been inqueued successfully.")
        return nil
    },
}

func init() {
    // Add this command as a child to your root command
    RootCmd.AddCommand(scheduleDastAutomationCmd)
}
