# Detection Name
Encoded powerShell Execution Detection

# Objective
Detect PowerShell execution using the -EncodedCommand/ -E parameter, commonly associated with obfuscated script execution and attacker tradecraft.

# Threat Context
Attackers frequently use encoded PowerShell commands to:
- evade detection,
- obfuscate payloads,
- execute malicious scripts.

This behaviour is commonly observed in:
- malware execution,
- phishing payloads,
- lateral movement,
- post-exploitation activity.

# Telemetry Source
- Sysmon Event ID 1
- Windows Process Creation Logs

# Detection Logic
Detect process creation events containing:
- powershell
- -EncodedCommand/ -E

# MITRE ATT&CK Mapping
- Tactic: Execution
- Technique: T1059.001 PowerShell

# False Positives
Potential legitimate sources:
- administrative automation,
- deployment scripts,
- IT management tooling.

# Investigation Guidance
Review:
- parent-child process relationships,
- user context,
- command-line arguments,
- execution frequency,
- correlated network activity.

# Future Improvements
Potential enhancements:
- Base64 decoding automation
- correlation with network telemetry
- suspicious parent-process detection
- allowlist implementation