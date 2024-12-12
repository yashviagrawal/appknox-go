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

// analysesCmd represents the analyses command
var sarifCmd = &cobra.Command{
	Use:   "sarif",
	Short: "Create SARIF report",
	Long:  `Create SARIF report`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("file id is required")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		fileID, err := strconv.Atoi(args[0])
		if err != nil {
			helper.PrintError("valid file id is required")
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
		outputFilePath, _ := cmd.Flags().GetString("output")
		timeoutMinutes, _ := cmd.Flags().GetInt("timeout")
		timeout := time.Duration(timeoutMinutes) * time.Minute
		helper.ConvertToSARIFReport(fileID,riskThresholdInt,outputFilePath,timeout)
	},
}

func init() {
	RootCmd.AddCommand(sarifCmd)
	sarifCmd.Flags().StringP(
		"risk-threshold", "r", "low", "Risk threshold to fail the command. Available options: low, medium, high")
	sarifCmd.PersistentFlags().StringP("output", "o", "report.sarif", "Output file path to save reports")
	sarifCmd.Flags().IntP(
		"timeout", "t", 30, "Static scan timeout in minutes for the CI check (default: 30)")
}
