# Office Application Spawning PowerShell Detection

## Objective

Detect PowerShell execution initiated by Microsoft Office applications.

## Threat Context

Microsoft Office applications are frequently abused by attackers to execute malicious code through macros, embedded scripts, and phishing documents.

A common attack pattern involves an Office application spawning PowerShell to execute payloads, download additional malware, or establish persistence.

This behaviour is uncommon during normal document usage and often warrants investigation.

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

Identify Office processes spawning PowerShell processes.

Parent Processes:
- WINWORD.EXE
- EXCEL.EXE
- OUTLOOK.EXE
- POWERPNT.EXE

Child Processes:
- powershell.exe
- pwsh.exe

## False Positive Considerations

Potential legitimate activity may include:

- Administrative automation
- Enterprise document workflows
- Internal business tooling

Review process command line, user context, and execution frequency before escalation.

## Future Improvements

- Detect Office spawning cmd.exe
- Detect Office spawning mshta.exe
- Correlate with network telemetry
- Detect encoded PowerShell payloads
- Detect Office child process chains