🟢 SOC WAR ROOM — OPERATION: THE PHANTOM POWERSHELL
Mission 01 — Initial Triage
Analyst objective

The first question is not:

"Is PowerShell malicious?"

It is:

"Why did Excel spawn PowerShell, what did PowerShell execute, what did it contact, and what happened afterward?"

Priority evidence


| Priority    | Evidence                                     | Why it matters                                       |
| ----------- | -------------------------------------------- | ---------------------------------------------------- |
| 🔴 Critical | Excel → PowerShell parent-child relationship | Establishes the execution chain                      |
| 🔴 Critical | Exact PowerShell command line                | Reveals intended activity                            |
| 🔴 Critical | `-EncodedCommand` presence + decoded content | Obfuscation may hide execution                       |
| 🔴 Critical | PowerShell network destination               | Determines whether execution communicated externally |
| 🔴 Critical | FILE-SRV-02 access                           | Determines possible data access                      |
| 🟠 High     | Excel attachment name/type/hash              | Links email delivery to execution                    |
| 🟠 High     | PowerShell execution timestamp               | Correlates all events                                |
| 🟠 High     | Username/session                             | Identifies account involved                          |
| 🟠 High     | Additional authentication                    | Determines possible lateral movement                 |
| 🟡 Medium   | User's normal behaviour                      | Helps distinguish unusual activity                   |
| 🟡 Medium   | Other recipients/endpoints                   | Determines campaign scope      





Primary data sources

Wazuh / Windows Security logs

4688 — Process Creation
4624 — Successful Logon
4663 — Object/File access

PowerShell logs

4104 — Script Block Logging

Sysmon

Event ID 1 — Process Creation
Event ID 3 — Network Connection
Potentially Event ID 11 — File Creation
Potentially Event ID 22 — DNS Query

Email/security telemetry

Sender
Recipient
Attachment name
Attachment type
Attachment hash
Delivery/open timestamp|





Initial triage conclusion

Status: Suspicious — investigation required.

The strongest initial signal isn't simply PowerShell.

It's:

Excel → PowerShell → encoded command → external network connection → finance file access

That is a correlated execution chain. Defender reporting "No Threat Found" does not independently establish that the activity was benign.

Mission 02 — Hunting Hypotheses
H1 — Malicious Excel attachment caused PowerShell execution

Hypothesis

FIN-WS-042 was compromised through a malicious Excel attachment that launched PowerShell.

Evidence required
Email delivery timestamp
Attachment filename
Attachment hash
Excel process creation
Excel → PowerShell parent-child relationship
PowerShell command line
4104 script contents
Encoded command decoded
Any child processes/files created afterward
Data sources
Email gateway
Sysmon Event ID 1
Windows 4688
PowerShell 4104
Endpoint/EDR telemetry
File hash database

Expected indicators

Possible indicators include:

excel.exe spawning powershell.exe
-EncodedCommand
Obfuscated PowerShell
Hidden/non-interactive execution
Download activity
New executable/script creation
Suspicious child processes
External network connection
False positives
Legitimate Excel automation
Approved macros/add-ins
Enterprise document-management software
Security/IT automation
Internal scripts triggered through Office
Current conclusion

PENDING.

The parent-child relationship strongly supports the hypothesis, but we need the email attachment and execution evidence to establish the initial access path.



H2 — Legitimate administrative automation

Hypothesis

The PowerShell activity was authorised automation performed by an approved user or application.

Evidence required
User identity
User's role
Script owner
Script path
Script signature
Change/ticket reference
Scheduled task/job information
Normal historical execution
Known enterprise software generating the activity
Destination IP/domain ownership
Data sources
Windows Event Logs
PowerShell logs
Sysmon
EDR
Change-management records
SIEM historical data
Asset/application inventory
Expected indicators

A legitimate automation chain would typically have:

Known script
Known administrator/service account
Consistent execution pattern
Expected destination
Approved change
Repeated historical behaviour
No unexplained finance-share access
False positives

A security/IT administrator could legitimately use PowerShell, including from an Office-related workflow.

Current conclusion

Not established.

The user saying "I only opened an Excel attachment" is not sufficient evidence for legitimacy.

H3 — Compromised workstation accessed sensitive data and communicated externally

Hypothesis

FIN-WS-042 was compromised and subsequently used for finance-file access and outbound communication.

Evidence required
4663 file access records
Exact files/directories accessed
User/account involved
FILE-SRV-02 authentication
4624 Logon Type 3
Sysmon Event ID 3
Destination IP/domain
DNS records
Process associated with network connection
Other endpoints communicating with same destination

Expected indicators
Multiple finance-share accesses
New SMB sessions
Unusual Logon Type 3
External connection from PowerShell
Access outside normal working pattern
Same destination contacted by other compromised hosts
Additional process creation
Remote authentication

False positives
Normal finance-user access
Scheduled file synchronization
Backup software
Approved network applications
Corporate proxy infrastructure
Current conclusion

Suspicious and requires validation.

The combination of network communication + finance-share access makes this materially more concerning than an isolated PowerShell event.


Mission 03 — Attack Timeline

We should build the timeline as an evidence chain, not as a story we assume happened.
EMAIL DELIVERY
     │
     ▼
Excel attachment received
     │
     ▼
USER OPENS EXCEL
     │
     ▼
EXCEL.EXE
     │
     ▼
POWERSHELL.EXE
     │
     ├── EncodedCommand
     │
     ▼
4104 SCRIPT EXECUTION
     │
     ▼
NETWORK CONNECTION
     │
     ▼
FILE-SRV-02
     │
     ▼
Finance share access
     │
     ▼
Additional authentication


Questions to answer from telemetry

1. What started PowerShell?

Expected evidence:

ParentImage = ...\EXCEL.EXE
Image       = ...\POWERSHELL.EXE
If Sysmon 1 confirms this, we have strong process-lineage evidence.


2. What command-line arguments were used?

Look for:CommandLine

Especially:-EncodedCommand or -e or -enc
Don't automatically classify every encoded command as malicious. The decoded content and execution context matter.



3. Was PowerShell hidden/non-interactive?

Look for arguments such as:

-WindowStyle Hidden
-NoProfile
-NonInteractive

These increase suspicion when combined with Office spawning PowerShell.

4. Did PowerShell create another process?

Search Sysmon Event ID 1 for:

ParentImage = powershell.exe

This could reveal:

powershell.exe
   ↓
cmd.exe
   ↓
another process

or other child processes.

5. Did PowerShell download or execute another file?

Correlate:

4104
Sysmon 1
Sysmon 3
Sysmon 11
EDR telemetry

We're looking for the chain:

PowerShell
   ↓
Network
   ↓
File creation
   ↓
Execution

That is much stronger evidence than PowerShell alone.



6. Which destination did it contact?

Use Sysmon 3 and correlate:

Source process
Source IP
Destination IP
Destination port
Timestamp

If DNS telemetry exists, correlate the destination IP with the queried domain.

7. Was the destination seen elsewhere?

This becomes a SIEM-wide hunt:

destination.ip == suspicious_IP

across all endpoints.

If multiple unrelated machines contacted the same infrastructure around the same time, the scope changes significantly.

Mission 04 — Detection Engineering
Detection Name

Microsoft Office Spawning Suspicious PowerShell

Telemetry
Sysmon Event ID 1
Windows Security Event ID 4688
PowerShell 4104 where available
Relevant fields
Image
ParentImage
CommandLine
ParentCommandLine
User
Computer
ProcessId
ParentProcessId
UtcTime
Sigma-like detection concept
selection:
    Image endswith:
        \powershell.exe
        \pwsh.exe

    ParentImage endswith:
        \excel.exe
        \winword.exe
        \outlook.exe
        \powerpnt.exe
        \msaccess.exe

condition:
    selection

Then increase confidence when the command line contains suspicious execution characteristics such as:

-EncodedCommand
-WindowStyle Hidden
-NoProfile
-NonInteractive
Severity

High

Not because PowerShell itself is inherently malicious, but because Office → PowerShell is an unusual process relationship that deserves investigation.

False positives
Approved macros
Enterprise automation
Security tools
IT administration
Internal business workflows
Analyst Response
Identify user.
Capture full process tree.
Capture PowerShell command line.
Retrieve 4104 events.
Decode encoded content safely.
Check network connections.
Check file creation.
Investigate email attachment.
Hunt the same indicators across endpoints.
Escalate/contain if malicious behaviour is confirmed.
Detection-engineering insight

A weak rule says:

IF powershell.exe exists → alert
A better rule says:

IF Office application
    └── spawns PowerShell
        └── with suspicious execution characteristics
            → alert

Context reduces noise.


Mission 05 — Lateral Movement & Data Access

If FIN-WS-042 is compromised, I would hunt in this order:

1. Authentication

Search:

4624 Logon Type 3

Look for:

Source workstation
Destination server
Account
Timestamp
Authentication package
Logon ID

Then correlate with:

4624 → 4672 → 4688

where available.

2. SMB

Investigate connections from FIN-WS-042 to:

FILE-SRV-02
other file servers
domain controllers
other workstations

Look for unusual destinations and timing.

3. Finance data access

For Event 4663:

SubjectUserName
ObjectName
AccessMask
ProcessName
Computer

The key question isn't simply:

"Were files accessed?"

It's:

"Which account accessed which sensitive objects, through which process, and at what time?"

4. RDP

Search for authentication associated with:

4624
Logon Type 10
RDP-related telemetry

Look for unexpected source/destination relationships.

5. Remote PowerShell

Hunt for:

PowerShell remoting
WinRM
remote sessions
PowerShell processes on other hosts
matching command lines
6. Credential access

Search for evidence associated with:

suspicious credential-related processes
unusual privilege assignment
LSASS access
credential dumping indicators
suspicious security-tool tampering

Don't assume credential theft just because lateral movement is possible. Find the evidence.

7. Same indicators across the environment

Search for:

same attachment hash
same PowerShell command
same encoded payload
same destination IP
same destination domain
same filename
same process tree

This determines whether FIN-WS-042 is an isolated incident or part of a broader campaign.

🔥 What do we collect BEFORE reimaging?

This is an important DFIR decision.

Do not immediately destroy the compromised state if evidence preservation is still possible and safe.

Before reimaging, preserve:

Endpoint evidence
Memory, where feasible
Process tree
Running processes
Network connections
PowerShell logs
Windows Security logs
Sysmon logs
EDR telemetry
Relevant files
Prefetch where applicable
Scheduled tasks
Persistence mechanisms
Browser/email artifacts where relevant
Attack evidence
Original Excel attachment
Attachment hash
Encoded PowerShell command
Decoded script
Destination IP/domain
Network timestamps
FILE-SRV-02 access records
Authentication records
Other affected endpoints
Why?

Because reimaging can remove evidence that answers:

How did the attacker get in?

What did they execute?

What did they access?

Where did they communicate?

Did they move elsewhere?

If you only reimage FIN-WS-042, you may restore the endpoint while leaving the initial-access mechanism, persistence, or other compromised hosts undiscovered.

Containment and evidence preservation should therefore be coordinated rather than treated as mutually exclusive.

Mission 06 — Containment Plan
Phase 1 — Stop potential spread
FIN-WS-042
     ↓
Network isolation
     ↓
Verify isolation

Do not simply assume isolation worked.

Confirm that expected network communication has stopped.

Phase 2 — Protect identity

Review the affected account.

Depending on evidence and organisational procedure:

Force credential reset
Revoke active sessions/tokens
Review privileged access
Check recent authentication
Investigate suspicious logons

Avoid automatically disabling an account before preserving necessary evidence unless the risk requires immediate action.

Phase 3 — Preserve the initial-access artifact

Preserve:

Email
 ↓
Attachment
 ↓
Hash
 ↓
Excel metadata

Then search the environment for that hash.

Phase 4 — Hunt globally

Search Wazuh/SIEM for:

same hash
same filename
same command line
same encoded command
same destination IP
same domain
same process relationship

This is where one endpoint becomes an incident scope investigation.

Phase 5 — Investigate FILE-SRV-02

Review:

4624
4663
other relevant file/share telemetry

Determine:

Which files were accessed?
Which account accessed them?
When?
From which workstation?
Was access normal?
Were files modified or only read?
Phase 6 — Preserve and escalate

Preserve relevant logs and endpoint evidence.

Notify the business owner because finance data may have been accessed.

Then determine whether:

eradication → recovery → monitoring

can safely begin.

🧠 Senior SOC Question
Which gives stronger context?
A
powershell.exe

versus

B
EXCEL.EXE
    ↓
POWERSHELL.EXE
    ↓
Encoded command
    ↓
External network connection
    ↓
FILE-SRV-02
    ↓
Finance file access

B provides substantially more investigative context because it describes a sequence of related events rather than an isolated process.

The important concept is event correlation.

A single PowerShell event has many legitimate explanations.

But when multiple telemetry sources align:

Process Creation
       +
PowerShell Script Block
       +
Network Connection
       +
Authentication
       +
File Access

the SOC can reconstruct what happened, when it happened, what process caused it, which account was involved, and what happened afterward.

That's the difference between:

"PowerShell ran."

and

"Excel launched PowerShell, PowerShell executed an encoded command, that process established an external connection, and the same user subsequently accessed finance resources."

Detection engineering should therefore focus not only on individual indicators, but also on relationships between processes and events.

🎯 My SOC assessment of the case so far

Based only on the scenario telemetry, I would classify FIN-WS-042 as:

🔴 High-priority suspicious activity — not a false positive at this stage.

But I would not yet write "confirmed compromise."

The evidence we still need to establish that conclusion is primarily:

1. Exact PowerShell command
2. Decoded payload
3. Excel attachment
4. Attachment hash
5. Network destination
6. FILE-SRV-02 accessed objects
7. Authentication context
8. Evidence of persistence/download/secondary execution
9. Same indicators elsewhere

That distinction is important for a real SOC analyst:

Suspicious ≠ malicious ≠ confirmed compromise.

We move between those states because of evidence, not because the scenario sounds scary.


