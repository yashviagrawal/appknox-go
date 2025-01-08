package cmd

import (
    "fmt"

    "github.com/spf13/cobra"
    // Import your helper package
    "github.com/appknox/appknox-go/helper"
)

// scheduleDastAutomationCmd represents the schedule DAST automation command
var scheduleDastAutomationCmd = &cobra.Command{
    Use:   "schedule-dast-automation <file_id>",
    Short: "Schedule a DAST automation for the specified file",
    Long: `Schedule a new Dynamic Application Security Testing (DAST) automation
for the specified file ID in Appknox. This command enqueues a dynamic scan process.`,
    Args: cobra.ExactArgs(1),
    RunE: func(cmd *cobra.Command, args []string) error {
        fileID := args[0]

        // Optionally print an initial message
        fmt.Printf("Scheduling DAST automation for file: %s\n", fileID)

        // Call the helper method — it handles client creation & API call
        if err := helper.ScheduleDastAutomation(fileID); err != nil {
            return fmt.Errorf("failed to schedule DAST: %v", err)
        }

        fmt.Println("Dynamic scan has been inqueued successfully.")
        return nil
    },
}

func init() {
    // Attach to your root command; change `RootCmd` to `rootCmd` if your root is lowercase.
    RootCmd.AddCommand(scheduleDastAutomationCmd)
}
