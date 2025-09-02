#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interactive bootstrap for Azure Monitor Linux Agent (RHEL) with AgentDirectToStore DCR.

- Prompts for required parameters (resource group, VM name, DCR name, Event Hub ID, Storage ID)
- Defaults location to "centralus", AMA version to "1.21"
- Guides you step by step
"""

import json
import sys
import subprocess
import shutil
import os
import tempfile
from datetime import datetime

# ---------- Helpers ----------

def run(cmd, check=True, capture=True):
    if isinstance(cmd, str):
        shell = True
    else:
        shell = False
    res = subprocess.run(
        cmd,
        shell=shell,
        check=check,
        capture_output=capture,
        text=True
    )
    return res.stdout.strip()

def az(*args):
    if shutil.which("az") is None:
        raise RuntimeError("Azure CLI not found in PATH.")
    cmd = ["az"] + list(args) + ["-o", "tsv"]
    return run(cmd)

def az_json(*args):
    cmd = ["az"] + list(args) + ["-o", "json"]
    out = run(cmd)
    return json.loads(out) if out else {}

def prompt(msg, default=None, required=False):
    if default:
        full = f"{msg} [{default}]: "
    else:
        full = f"{msg}: "
    while True:
        val = input(full).strip()
        if not val and default:
            return default
        if not val and required:
            print("This is required.")
        else:
            return val

def info(msg): print(f"[INFO] {msg}")

# ---------- Core (simplified for demo) ----------

def main():
    print("=== AMA Direct-to-Store Setup (Interactive) ===")

    rg = prompt("Resource Group", required=True)
    vm = prompt("VM Name (RHEL)", required=True)
    dcr = prompt("Data Collection Rule Name", required=True)
    ehid = prompt("Event Hub Resource ID", required=True)
    stid = prompt("Storage Account Resource ID", required=True)
    loc = prompt("Location", default="centralus")
    cont = prompt("Blob Container Name", default="ama-logs")
    agentv = prompt("Agent version", default="1.21")
    use_uai = prompt("User Assigned Identity Resource ID (leave blank for system-assigned)", default="")

    auto_upgrade = prompt("Enable minor auto-upgrade? (y/n)", default="y")
    auto_upgrade_flag = auto_upgrade.lower().startswith("y")

    plan = {
        "resourceGroup": rg,
        "vmName": vm,
        "dcrName": dcr,
        "location": loc,
        "eventHubId": ehid,
        "storageId": stid,
        "container": cont,
        "agentVersion": agentv,
        "identityMode": "UserAssigned" if use_uai else "SystemAssigned",
        "autoUpgradeMinorVersion": auto_upgrade_flag
    }

    print("\n=== Planned configuration ===")
    print(json.dumps(plan, indent=2))

    confirm = prompt("Proceed with deployment? (y/n)", default="n")
    if confirm.lower() != "y":
        print("Aborting.")
        sys.exit(0)

    # At this point you'd call the same functions from the previous script:
    # - ensure identity (system-assigned or UAI)
    # - grant RBAC on EH + Storage
    # - deploy DCR (AgentDirectToStore)
    # - associate DCR to VM
    # - install AMA extension

    info(">>> This is where the deployment logic would run <<<")
    # For brevity, just echoing. Reuse the functions from the full script I gave earlier.

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)
