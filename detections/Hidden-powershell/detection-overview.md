# Hidden PowerShell Execution Detection

## Objective

Detect PowerShell executions launched with hidden window parameters, which may indicate attempts to conceal script execution from users and evade casual observation.

## Threat Context

PowerShell is frequently abused by attackers for execution, persistence, and post-exploitation activities.

One common technique involves launching PowerShell with a hidden window using parameters such as:

- -WindowStyle Hidden
- -w hidden

This behaviour can be used to:

- Execute malicious scripts without user visibility
- Launch payloads delivered through phishing campaigns
- Run persistence mechanisms in the background
- Conceal post-exploitation activities

While legitimate administrative tools may also use hidden PowerShell execution, the behaviour warrants investigation when observed unexpectedly.

## Telemetry Sources

### Sysmon

- Event ID 1 (Process Creation)

### Windows Event Logs

- Process creation telemetry
- Command-line arguments

### Microsoft Sentinel

- Sysmon events ingested through Azure Monitor Agent
- Log Analytics Workspace

## Detection Logic

The detection identifies PowerShell executions containing hidden window execution parameters.

Indicators:

- powershell.exe
- pwsh.exe
- -WindowStyle Hidden
- -w hidden

## Detection Workflow

1. Generate telemetry using controlled PowerShell execution
2. Validate Sysmon Event ID 1 generation
3. Confirm ingestion into Microsoft Sentinel
4. Execute KQL detection query
5. Create Sentinel analytics rule
6. Investigate resulting alerts
7. Document findings and tuning opportunities

## Potential Impact

Successful detection may identify:

- Malware execution
- Script-based attacks
- Hidden administrative abuse
- Suspicious automation activity

## False Positive Considerations

Legitimate sources may include:

- Enterprise administration scripts
- Software deployment platforms
- Monitoring tools
- Configuration management systems

Analysts should review:

- Parent process
- User context
- Host role
- Frequency of execution
- Associated activity

## Future Improvements

Potential enhancements include:

- Detecting shortened PowerShell arguments
- Correlating with network activity
- Correlating with encoded PowerShell execution
- Building process lineage detections
- Implementing allowlists for approved administrative tooling