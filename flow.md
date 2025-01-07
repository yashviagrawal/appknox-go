```mermaid
flowchart TB
    A[Start: RunDastCheck(fileID, riskThreshold)] --> B[Get dynamic_status from /files/:file_id]

    B --> C{dynamic_status}
    C -- "== 1 (INQUEUE)" --> D[Print "Status: inqueue" & Exit]
    C -- "== 0 (NONE)" --> E[Call getLatestDynamicScan()]
    C -- "other" --> F[Call getLatestDynamicScan()]

    E --> G{scanInfo is nil?}
    G -- "Yes" --> H[Print "No dynamic scan is running" & Exit]
    G -- "No" --> I[Check scanInfo.Status]

    F --> J{scanInfo is nil?}
    J -- "Yes" --> K[Print "No dynamic scan is currently running" & Exit]
    J -- "No" --> L[Check scanInfo.Status]

    I --> M{scanInfo.Status}
    M -- "== 22 (ANALYSIS_COMPLETED)" --> N[Print "Dynamic scan completed" & Show vulns & Exit]
    M -- "== 23|24|25 (TIMEOUT|ERROR|CANCEL)" --> O[Print final status & error_message & Exit]
    M -- "else" --> P[Dynamic scan in progress -> Poll until finished]

    L --> Q{scanInfo.Status}
    Q -- "== 22 (ANALYSIS_COMPLETED)" --> R[Print "Dynamic scan completed" & Show vulns & Exit]
    Q -- "== 23|24|25" --> S[Print final status & error_message & Exit]
    Q -- "else" --> T[Dynamic scan in progress -> Poll until finished]

    P --> P1[Wait 60s, getLatestDynamicScan again]
    P1 --> P2[Check updated scanInfo.Status -> same end states as above]
    T --> T1[Wait 60s, getLatestDynamicScan again]
    T1 --> T2[Check updated scanInfo.Status -> same end states as above]
