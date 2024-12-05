package cmd

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/appknox/appknox-go/helper"
	"github.com/spf13/cobra"
)

// cicheckCmd represents the cicheck command
var cicheckCmd = &cobra.Command{
	Use:   "cicheck",
	Short: "Check for vulnerabilities based on risk threshold.",
	Long:  `List all the vulnerabilities with the risk threshold greater or equal than the provided and fail the command.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("file id is required")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		fileID, err := strconv.Atoi(args[0])
		if err != nil {
			err := errors.New("Valid file id is required")
			helper.PrintError(err)
			os.Exit(1)
		}
		riskThreshold, _ := cmd.Flags().GetString("risk-threshold")
		riskThresholdLower := strings.ToLower(riskThreshold)
		var riskThresholdInt int
		switch riskThresholdStr := riskThresholdLower; riskThresholdStr {
		case "low":
			riskThresholdInt = 1
		case "medium":
			riskThresholdInt = 2
		case "high":
			riskThresholdInt = 3
		case "critical":
			riskThresholdInt = 4
		default:
			err := errors.New("valid risk threshold is required")
			helper.PrintError(err)
			os.Exit(1)
		}
		timeoutMinutes, _ := cmd.Flags().GetInt("timeout")
		timeout := time.Duration(timeoutMinutes) * time.Minute
		
		helper.ProcessCiCheck(fileID, riskThresholdInt, timeout)
	},
}

func init() {
	RootCmd.AddCommand(cicheckCmd)
	cicheckCmd.Flags().StringP(
		"risk-threshold", "r", "low", "Risk threshold to fail the command. Available options: low, medium, high")
	cicheckCmd.Flags().IntP(
			"timeout", "t", 30, "Static scan timeout in minutes for the CI check (default: 30)")
	
}
