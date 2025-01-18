package appknox

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/appknox/appknox-go/appknox/enums"
)

// DynamicScanService handles communication with the dynamic scan (DAST) related
// methods of the Appknox API.
type DynamicScanService service

// DRFResponseDynamicScan represents the DRF response for the Appknox dynamic scan API.
type DRFResponseDynamicScan struct {
	Count    int            `json:"count,omitempty"`
	Next     string         `json:"next,omitempty"`
	Previous string         `json:"previous,omitempty"`
	Results  []*DynamicScan `json:"results"`
}

// DynamicScanResponse is a wrapper on DRFResponseDynamicScan which helps
// to execute further operations on DRFResponseDynamicScan results.
type DynamicScanResponse struct {
	r *DRFResponseDynamicScan
	s *DynamicScanService
	c *context.Context
}

// DynamicScan represents a single dynamic scan object (DAST) in Appknox.
type DynamicScan struct {
	ID                       int                         `json:"id,omitempty"`
	File                     int                         `json:"file,omitempty"`
	Mode                     enums.DynamicScanModeType   `json:"mode,omitempty"`
	Status                   enums.DynamicScanStatusType `json:"status,omitempty"`
	EnableAPICapture         bool                        `json:"enable_api_capture,omitempty"`
	MoriartyDynamicScanID    string                      `json:"moriarty_dynamicscan_id,omitempty"`
	MoriartyDynamicScanToken string                      `json:"moriarty_dynamicscan_token,omitempty"`
	DeviceUsed               map[string]interface{}      `json:"device_used,omitempty"`
	ErrorCode                string                      `json:"error_code,omitempty"`
	ErrorMessage             string                      `json:"error_message,omitempty"`
	CreatedOn                *time.Time                  `json:"created_on,omitempty"`
	UpdatedOn                *time.Time                  `json:"updated_on,omitempty"`
	EndedOn                  *time.Time                  `json:"ended_on,omitempty"`
	AutoShutDownOn           *time.Time                  `json:"auto_shutdown_on,omitempty"`
	IsAnalysisDone           bool                        `json:"is_analysis_done,omitempty"`
}

// ListByFile lists the dynamic scans for a given file ID.
func (s *DynamicScanService) ListByFile(ctx context.Context, fileID int) ([]*DynamicScan, *DynamicScanResponse, error) {
	u := fmt.Sprintf("api/v2/files/%v/dynamicscans", fileID)
	req, err := s.client.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}

	var drfResponse DRFResponseDynamicScan
	_, err = s.client.Do(ctx, req, &drfResponse)
	if err != nil {
		return nil, nil, err
	}
	resp := DynamicScanResponse{
		r: &drfResponse,
		s: s,
		c: &ctx,
	}
	return drfResponse.Results, &resp, nil
}

// ScheduleDastAutomation sends a POST request to schedule a DAST automation
// for the specified file ID.
func (s *DynamicScanService) ScheduleDastAutomation(ctx context.Context, fileID int) (*Response, error) {
	u := fmt.Sprintf("/api/dynamicscan/%d/schedule_automation", fileID)
	req, err := s.client.NewRequest(http.MethodPost, u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(ctx, req, nil)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
