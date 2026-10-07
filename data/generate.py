"""Seeded generator for benign Sysmon-style Windows telemetry.

Produces a week of activity across the 12 hosts in assets.yml: background noise plus benign
activity that deliberately trips the detection rules (the false-positive population). It
generates no attack activity. True positives come from real public telemetry (OTRF
Security-Datasets) loaded by data/ingest/otrf.py and placed into this same timeline.
"""

from __future__ import annotations

import base64
import hashlib
import random
import string
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent
START = datetime(2026, 9, 1, tzinfo=UTC)
DAYS = 7

SYS32 = "C:\\Windows\\System32"
PS = f"{SYS32}\\WindowsPowerShell\\v1.0\\powershell.exe"
CMD = f"{SYS32}\\cmd.exe"
OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16"

# Benign infrastructure the background noise talks to.
BENIGN_DOMAINS = {
    "login.microsoftonline.com": "13.107.42.14",
    "outlook.office365.com": "52.97.146.162",
    "www.google.com": "142.250.72.196",
    "teams.microsoft.com": "52.113.194.132",
    "update.googleapis.com": "142.250.80.35",
    "www.powershellgallery.com": "13.107.246.40",
    "github.com": "140.82.112.3",
    "slack.com": "34.205.12.98",
}

def ps_enc(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


def good_hash(image: str) -> str:
    return hashlib.sha256(f"good:{image.lower()}".encode()).hexdigest()


@dataclass
class Proc:
    guid: str
    host: str
    user: str
    image: str
    command_line: str
    sha256: str
    pid: int


@dataclass
class Generator:
    seed: int = 1337
    events: list[dict[str, Any]] = field(default_factory=list)
    intel: dict[str, dict[str, Any]] = field(default_factory=lambda: {"ip": {}, "hash": {}, "domain": {}})
    groups: dict[str, str] = field(default_factory=dict)  # event_uid -> generator group (for splits)

    def __post_init__(self) -> None:
        self.rng = random.Random(self.seed)
        assets = yaml.safe_load((ROOT / "assets.yml").read_text())
        self.hosts: dict[str, dict] = assets["hosts"]
        self.workstations = [h for h, a in self.hosts.items() if a["role"] == "workstation"]
        self.servers = [h for h in self.hosts if h not in self.workstations]
        self.admins: list[str] = assets["admins"]
        self._group: str = "background"
        self._ip_octet = 20
        self._roots: dict[str, Proc] = {}
        for d, ip in BENIGN_DOMAINS.items():
            self.intel["domain"][d] = {"domain": d, "age_days": self.rng.randint(2000, 9000),
                                       "reputation": "clean", "malicious_votes": 0, "categories": ["business"]}
            self.intel["ip"][ip] = {"ip": ip, "abuse_confidence": 0, "asn": "AS8075 Microsoft" if ip.startswith(("13.", "52.")) else "AS15169 Google",
                                    "country": "US", "total_reports": 0}

    # ------------------------------------------------------------------ primitives
    def guid(self) -> str:
        return "{" + str(uuid.UUID(int=self.rng.getrandbits(128))) + "}"

    def uid(self) -> str:
        return "evt-" + "".join(self.rng.choices(string.hexdigits.lower()[:16], k=12))

    def rand_name(self, n: int = 8) -> str:
        return "".join(self.rng.choices(string.ascii_lowercase + string.digits, k=n))

    def ts(self, day: int | None = None, work_hours: bool = True) -> datetime:
        day = self.rng.randrange(DAYS) if day is None else day
        hour = self.rng.randint(8, 18) if work_hours else self.rng.randint(0, 23)
        return START + timedelta(days=day, hours=hour, minutes=self.rng.randint(0, 59), seconds=self.rng.randint(0, 59))

    def _emit(self, ts: datetime, host: str, user: str, event_id: int, **fields: Any) -> dict[str, Any]:
        ev = {
            "event_uid": self.uid(), "timestamp": ts.isoformat(), "host": host, "user": user, "event_id": event_id,
            "process_guid": None, "parent_process_guid": None, "image": None, "parent_image": None,
            "command_line": None, "parent_command_line": None, "sha256": None, "pid": None,
            "target_image": None, "granted_access": None, "dst_ip": None, "dst_port": None, "query_name": None,
            "target_filename": None, "registry_key": None, "registry_value": None, "service_name": None,
            "service_path": None,
        }
        ev.update(fields)
        self.events.append(ev)
        self.groups[ev["event_uid"]] = self._group
        return ev

    def root(self, host: str, user: str) -> Proc:
        key = f"{host}|{user}"
        if key not in self._roots:
            image = "C:\\Windows\\explorer.exe" if user not in ("SYSTEM", "svc_sccm") else f"{SYS32}\\services.exe"
            self._roots[key] = Proc(self.guid(), host, user, image, image, good_hash(image), self.rng.randint(500, 9000))
        return self._roots[key]

    def proc(self, ts: datetime, parent: Proc, image: str, cmd: str, user: str | None = None,
             sha256: str | None = None) -> Proc:
        p = Proc(self.guid(), parent.host, user or parent.user, image, cmd, sha256 or good_hash(image),
                 self.rng.randint(1000, 30000))
        self._emit(ts, p.host, p.user, 1, process_guid=p.guid, parent_process_guid=parent.guid, image=image,
                   parent_image=parent.image, command_line=cmd, parent_command_line=parent.command_line,
                   sha256=p.sha256, pid=p.pid)
        if p.sha256 == good_hash(image) and p.sha256 not in self.intel["hash"]:
            self.intel["hash"][p.sha256] = {"sha256": p.sha256, "detections": 0, "total_engines": 72,
                                            "family": None, "signed": True, "first_seen": "2023-01-10",
                                            "names": [image.split("\\")[-1]]}
        return p

    def net(self, ts: datetime, p: Proc, ip: str, port: int) -> None:
        self._emit(ts, p.host, p.user, 3, process_guid=p.guid, image=p.image, dst_ip=ip, dst_port=port)

    def dns(self, ts: datetime, p: Proc, domain: str) -> None:
        self._emit(ts, p.host, p.user, 22, process_guid=p.guid, image=p.image, query_name=domain)

    def file(self, ts: datetime, p: Proc, path: str) -> None:
        self._emit(ts, p.host, p.user, 11, process_guid=p.guid, image=p.image, target_filename=path)

    def reg(self, ts: datetime, p: Proc, key: str, value: str) -> None:
        self._emit(ts, p.host, p.user, 13, process_guid=p.guid, image=p.image, registry_key=key, registry_value=value)

    def access(self, ts: datetime, p: Proc, target: str, granted: str) -> None:
        self._emit(ts, p.host, p.user, 10, process_guid=p.guid, image=p.image, target_image=target,
                   granted_access=granted)

    def service(self, ts: datetime, host: str, name: str, path: str, user: str = "SYSTEM") -> None:
        self._emit(ts, host, user, 7045, service_name=name, service_path=path,
                   image=f"{SYS32}\\services.exe")

    def begin(self, group: str) -> None:
        self._group = group

    # ------------------------------------------------------------------ background
    def background(self) -> None:
        self.begin("background")
        apps = [
            ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "\"chrome.exe\" --type=renderer", "www.google.com"),
            (f"{OFFICE}\\OUTLOOK.EXE", "\"OUTLOOK.EXE\"", "outlook.office365.com"),
            ("C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", "\"Teams.exe\" --system-initiated", "teams.microsoft.com"),
            (f"{SYS32}\\notepad.exe", "notepad.exe", None),
            ("C:\\Program Files\\Slack\\slack.exe", "\"slack.exe\"", "slack.com"),
        ]
        for host, asset in self.hosts.items():
            user = asset["owner"] if asset["role"] == "workstation" else self.rng.choice(self.admins)
            for day in range(DAYS):
                for _ in range(self.rng.randint(25, 40)):
                    image, cmd, domain = self.rng.choice(apps)
                    image = image.replace("{u}", user)
                    t = self.ts(day)
                    p = self.proc(t, self.root(host, user), image, cmd)
                    if domain:
                        self.dns(t + timedelta(seconds=1), p, domain)
                        self.net(t + timedelta(seconds=2), p, BENIGN_DOMAINS[domain], 443)
                svc = self.root(host, "SYSTEM")
                for _ in range(self.rng.randint(5, 10)):
                    self.proc(self.ts(day, False), svc, f"{SYS32}\\svchost.exe", "svchost.exe -k netsvcs -p", "SYSTEM")

    # ------------------------------------------------------------------ benign rule triggers (FPs)
    def benign(self) -> None:
        r = self.rng
        n = 0

        def grp(kind: str) -> None:
            nonlocal n
            n += 1
            self.begin(f"benign:{kind}:{n}")

        sccm_scripts = ["Get-WmiObject -Class Win32_Product | Select Name,Version",
                        "Invoke-WmiMethod -Namespace root\\ccm -Class SMS_Client -Name TriggerSchedule '{00000000-0000-0000-0000-000000000021}'",
                        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
                        "Get-BitLockerVolume | Select MountPoint,ProtectionStatus"]
        for _ in range(26):  # SCCM client runs encoded PowerShell (R001)
            grp("sccm_encoded_ps")
            host = r.choice(self.workstations)
            ccm = self.proc(self.ts(), self.root(host, "SYSTEM"), "C:\\Windows\\CCM\\CcmExec.exe", "C:\\Windows\\CCM\\CcmExec.exe", "SYSTEM")
            self.proc(self.ts(), ccm, PS, f"powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {ps_enc(r.choice(sccm_scripts))}", "SYSTEM")

        for _ in range(12):  # admins with encoded PowerShell on servers (R001, ambiguous-looking)
            grp("admin_encoded_ps")
            host, user = r.choice(self.servers), r.choice(self.admins)
            t = self.ts()
            ise = self.proc(t, self.root(host, user), PS, "powershell.exe")
            script = r.choice(["Get-ADUser -Filter * -Properties LastLogonDate | Export-Csv C:\\Reports\\stale.csv",
                               "Restart-Service -Name W3SVC -Force", "Get-SmbShare | Format-Table",
                               "Get-EventLog -LogName System -Newest 50"])
            self.proc(t + timedelta(seconds=5), ise, PS, f"powershell.exe -NoProfile -enc {ps_enc(script)}")

        for _ in range(18):  # finance add-in launches a batch file from Excel (R002)
            grp("office_child")
            host = r.choice(["WS-003", "WS-006"])
            user = self.hosts[host]["owner"]
            t = self.ts()
            xl = self.proc(t, self.root(host, user), f"{OFFICE}\\EXCEL.EXE", f"\"{OFFICE}\\EXCEL.EXE\" \"\\\\SRV-FILE01\\finance\\Q3-close.xlsm\"")
            self.proc(t + timedelta(seconds=30), xl, CMD, f"cmd.exe /c \"\\\\SRV-FILE01\\finance\\macros\\refresh_{r.choice(['gl', 'ap', 'ar'])}.bat\"")

        for _ in range(20):  # Defender / Task Manager touching LSASS (R003)
            grp("lsass_benign")
            host = r.choice(self.workstations + self.servers)
            if r.random() < 0.7:
                p = self.proc(self.ts(), self.root(host, "SYSTEM"), "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24080.9-0\\MsMpEng.exe", "MsMpEng.exe", "SYSTEM")
                self.access(self.ts(), p, f"{SYS32}\\lsass.exe", "0x1410")
            else:
                user = self.hosts[host]["owner"] if host in self.workstations else r.choice(self.admins)
                p = self.proc(self.ts(), self.root(host, user), f"{SYS32}\\Taskmgr.exe", "\"C:\\Windows\\system32\\taskmgr.exe\" /4")
                self.access(self.ts(), p, f"{SYS32}\\lsass.exe", "0x1410")

        vendors = [("gupdate", "\"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe\" /svc"),
                   ("AdobeARMservice", "\"C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\armsvc.exe\""),
                   ("ZoomCptService", "\"C:\\Program Files\\Common Files\\Zoom\\Support\\CptService.exe\" -user_path"),
                   ("WinDefend", "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24080.9-0\\MsMpEng.exe\""),
                   ("VeeamAgent", "\"C:\\Program Files\\Veeam\\Endpoint Backup\\Veeam.EndPoint.Service.exe\"")]
        for _ in range(18):  # vendor service installs (R004)
            grp("vendor_service")
            host = r.choice(list(self.hosts))
            msi = self.proc(self.ts(), self.root(host, "SYSTEM"), f"{SYS32}\\msiexec.exe", "C:\\Windows\\system32\\msiexec.exe /V", "SYSTEM")
            name, path = r.choice(vendors)
            self.service(self.ts(), host, name, path)
            _ = msi

        for _ in range(14):  # admins inspecting certificates (R005)
            grp("certutil_admin")
            host, user = r.choice(self.servers), r.choice(self.admins)
            c = self.proc(self.ts(), self.root(host, user), CMD, "cmd.exe")
            self.proc(self.ts(), c, f"{SYS32}\\certutil.exe", r.choice(["certutil -store My", "certutil -verify C:\\certs\\web01.cer",
                                                                     "certutil -dump C:\\certs\\root-ca.cer", "certutil -viewstore Root"]))

        tasks = [("Adobe Acrobat Update Task", "C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe"),
                 ("GoogleUpdateTaskMachineUA", "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /ua /installsource scheduler"),
                 ("OneDrive Standalone Update Task-S-1-5-21", "%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe")]
        for _ in range(16):  # vendor scheduled tasks (R006)
            grp("vendor_task")
            host = r.choice(self.workstations)
            name, tr = r.choice(tasks)
            msi = self.proc(self.ts(), self.root(host, "SYSTEM"), f"{SYS32}\\msiexec.exe", "msiexec.exe /V", "SYSTEM")
            self.proc(self.ts(), msi, f"{SYS32}\\schtasks.exe", f"schtasks.exe /create /tn \"{name}\" /tr \"{tr}\" /sc daily /f", "SYSTEM")

        for _ in range(26):  # helpdesk / admin discovery (R007)
            grp("admin_discovery")
            if r.random() < 0.5:
                host, user = r.choice(self.servers), r.choice(self.admins)
            else:
                host = r.choice(self.workstations)
                user = self.hosts[host]["owner"]
            c = self.proc(self.ts(), self.root(host, user), CMD, "\"C:\\Windows\\system32\\cmd.exe\"")
            image, cmd = r.choice([(f"{SYS32}\\ipconfig.exe", "ipconfig /all"), (f"{SYS32}\\whoami.exe", "whoami"),
                                   (f"{SYS32}\\net.exe", "net use"), (f"{SYS32}\\systeminfo.exe", "systeminfo")])
            self.proc(self.ts(), c, image, cmd)

        for _ in range(16):  # rundll32 for printers / control panel (R008)
            grp("rundll32_benign")
            host = r.choice(self.workstations)
            user = self.hosts[host]["owner"]
            self.proc(self.ts(), self.root(host, user), f"{SYS32}\\rundll32.exe",
                      r.choice(["rundll32.exe printui.dll,PrintUIEntry /in /n \\\\SRV-FILE01\\Floor2-HP",
                                "rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
                                "rundll32.exe C:\\Windows\\system32\\inetcpl.cpl,ClearMyTracksByProcess 8"]))

        for _ in range(10):  # installer registering COM DLLs (R009)
            grp("regsvr32_benign")
            host = r.choice(list(self.hosts))
            msi = self.proc(self.ts(), self.root(host, "SYSTEM"), f"{SYS32}\\msiexec.exe", "msiexec.exe /V", "SYSTEM")
            self.proc(self.ts(), msi, f"{SYS32}\\regsvr32.exe",
                      r.choice(["regsvr32.exe /s \"C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\AcroPDFImpl64.dll\"",
                                "regsvr32.exe /s \"C:\\Program Files\\Microsoft Office\\root\\VFS\\ProgramFilesCommonX64\\Microsoft Shared\\OFFICE16\\MSOXMLMF.DLL\""]), "SYSTEM")

        for _ in range(18):  # OneDrive / Teams / SecurityHealth run keys (R010)
            grp("runkey_benign")
            host = r.choice(self.workstations)
            user = self.hosts[host]["owner"]
            name, val = r.choice([("OneDrive", f"\"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background"),
                                  ("com.squirrel.Teams.Teams", f"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Teams\\Update.exe --processStart \"Teams.exe\""),
                                  ("SecurityHealth", "%windir%\\system32\\SecurityHealthSystray.exe")])
            image = val.split("\"")[1] if val.startswith("\"") else val.split(" ")[0]
            p = self.proc(self.ts(), self.root(host, user), image, val)
            self.reg(self.ts(), p, f"HKU\\{user}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{name}", val)

        for _ in range(12):  # SCCM inventory via WMIC against workstations (R011)
            grp("wmic_inventory")
            user = "svc_sccm"
            c = self.proc(self.ts(), self.root("SRV-SCCM01", user), CMD, "cmd.exe /c inventory.cmd", user)
            self.proc(self.ts(), c, f"{SYS32}\\wbem\\WMIC.exe",
                      f"wmic /node:{r.choice(self.workstations)} computersystem get model,manufacturer /format:csv", user)

        for _ in range(14):  # PowerShell talking to the PowerShell Gallery (R012)
            grp("ps_gallery")
            host, user = r.choice(self.servers), r.choice(self.admins)
            t = self.ts()
            p = self.proc(t, self.root(host, user), PS, f"powershell.exe -Command Install-Module {r.choice(['PSWindowsUpdate', 'Az.Accounts', 'Pester'])} -Scope CurrentUser")
            self.dns(t + timedelta(seconds=1), p, "www.powershellgallery.com")
            self.net(t + timedelta(seconds=2), p, BENIGN_DOMAINS["www.powershellgallery.com"], 443)

    # ------------------------------------------------------------------ output
    def build(self) -> Generator:
        self.background()
        self.benign()
        self.events.sort(key=lambda e: e["timestamp"])
        return self
