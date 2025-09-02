#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Apply Azure Monitor (AMA) AgentDirectToStore using an exported DCR template.

- Reads ./DCR_deploy_new.json (exported from an existing DCR)
- Patches to AgentDirectToStore, updates destinations (Event Hub + Storage Blob),
  and (optionally) overrides DCR name + location
- Creates/attaches Managed Identity on a target RHEL VM
- Grants RBAC (EH Data Sender, Storage Blob Data Contributor)
- Deploys DCR, associates to VM, installs AzureMonitorLinuxAgent v1.21 with minor auto-upgrade

Prereqs:
  - Azure CLI installed (az) and logged in (`az login`)
  - Python 3.8+

Usage (interactive prompts):
  python ama_apply_exported_dcr.py
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime

TEMPLATE_FILENAME = "DCR_deploy_new.json"

# ---------- Shell helpers ----------

def run(cmd, check=True, capture=True):
    shell = isinstance(cmd, str)
    try:
        res = subprocess.run(cmd, shell=shell, check=check,
                             capture_output=capture, text=True)
        return res.stdout.strip()
    except subprocess.CalledProcessError as e:
        msg = e.stderr.strip() or e.stdout.strip() or str(e)
        raise RuntimeError(f"Command failed: {cmd}\n{msg}") from e

def az(*args, fmt="tsv"):
    if shutil.which("az") is None:
        raise RuntimeError("Azure CLI 'az' not found in PATH.")
    cmd = ["az"] + list(args)
    if fmt:
        cmd += ["-o", fmt]
    return run(cmd)

def az_json(*args):
    out = az(*args, fmt="json")
    return json.loads(out) if out else {}

def info(msg): print(f"[INFO] {msg}")
def warn(msg): print(f"[WARN] {msg}")
def err (msg): print(f"[ERROR] {msg}", file=sys.stderr)

def prompt(msg, default=None, required=False):
    q = f"{msg}"
    if default not in (None, ""):
        q += f" [{default}]"
    q += ": "
    while True:
        val = input(q).strip()
        if not val and default not in (None, ""):
            return default
        if not val and required:
            print("This is required.")
            continue
        return val

# ---------- ARM template helpers ----------

def _iter_resources(obj):
    """Yield all resources arrays recursively in an ARM template."""
    if isinstance(obj, dict):
        if "resources" in obj and isinstance(obj["resources"], list):
            for r in obj["resources"]:
                yield r
                # nested resources may exist
                yield from _iter_resources(r)
        # Also check nested 'resources' in 'template' (linked templates)
        if "template" in obj and isinstance(obj["template"], dict):
            yield from _iter_resources(obj["template"])
    elif isinstance(obj, list):
        for it in obj:
            yield from _iter_resources(it)

def find_dcr_resources(template_json):
    """Return a list of DCR resource dicts inside the template."""
    res = []
    for r in _iter_resources(template_json):
        if isinstance(r, dict) and r.get("type") == "Microsoft.Insights/dataCollectionRules":
            res.append(r)
    return res

def ensure_datasources_linux_defaults(props: dict):
    ds = props.setdefault("dataSources", {})
    # Minimal safe defaults if missing
    if "syslog" not in ds or not ds["syslog"]:
        ds["syslog"] = [{
            "streams": ["Microsoft-Syslog"],
            "facilityNames": ["auth","authpriv","daemon","kern","syslog","user"],
            "logLevels": ["Error","Critical","Alert","Emergency","Warning","Notice","Info"],
            "name": "linuxSyslog"
        }]
    if "performanceCounters" not in ds or not ds["performanceCounters"]:
        ds["performanceCounters"] = [{
            "streams": ["Microsoft-Perf"],
            "samplingFrequencyInSeconds": 15,
            "counterSpecifiers": [
                "processor.percentageProcessorTime",
                "memory.availableMemory",
                "logicaldisk.percentFreeSpace",
                "network.totalBytes"
            ],
            "name": "linuxPerf"
        }]

def patch_dcr_resource(dcr_res: dict, *,
                       dcr_name_override: str | None,
                       location_override: str | None,
                       eventhub_id: str,
                       storage_id: str,
                       container_name: str,
                       eh_dest_name: str = "ehDest",
                       blob_dest_name: str = "blobDest"):
    """Force AgentDirectToStore and wire EH + Blob destinations + dataFlows."""
    # Override name/location if provided (use literals)
    if dcr_name_override:
        dcr_res["name"] = dcr_name_override
    if location_override:
        dcr_res["location"] = location_override

    # Properties
    props = dcr_res.setdefault("properties", {})
    dcr_res["kind"] = "AgentDirectToStore"

    # Ensure Linux dataSources present
    ensure_datasources_linux_defaults(props)

    # Destinations
    dest = props.setdefault("destinations", {})
    ehs = dest.setdefault("eventHubsDirect", [])
    blobs = dest.setdefault("storageBlobsDirect", [])

    # Upsert EH destination
    if ehs:
        ehs[0]["name"] = eh_dest_name
        ehs[0]["eventHubResourceId"] = eventhub_id
    else:
        ehs.append({
            "name": eh_dest_name,
            "eventHubResourceId": eventhub_id
        })

    # Upsert Blob destination
    if blobs:
        blobs[0]["name"] = blob_dest_name
        blobs[0]["storageAccountResourceId"] = storage_id
        blobs[0]["containerName"] = container_name
    else:
        blobs.append({
            "name": blob_dest_name,
            "storageAccountResourceId": storage_id,
            "containerName": container_name
        })

    # Data flows: ensure Syslog + Perf go to both EH + Blob
    flows = props.setdefault("dataFlows", [])
    if not flows:
        flows.extend([
            {"streams": ["Microsoft-Syslog"], "destinations": [eh_dest_name, blob_dest_name]},
            {"streams": ["Microsoft-Perf"],   "destinations": [eh_dest_name, blob_dest_name]}
        ])
    else:
        for f in flows:
            dests = f.setdefault("destinations", [])
            for need in (eh_dest_name, blob_dest_name):
                if need not in dests:
                    dests.append(need)

def load_and_patch_template(path: str,
                            dcr_name_override: str | None,
                            location_override: str | None,
                            eventhub_id: str,
                            storage_id: str,
                            container_name: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        tpl = json.load(f)

    dcrs = find_dcr_resources(tpl)
    if not dcrs:
        raise RuntimeError("No Microsoft.Insights/dataCollectionRules resources found in template.")

    for dcr in dcrs:
        patch_dcr_resource(
            dcr,
            dcr_name_override=dcr_name_override,
            location_override=location_override,
            eventhub_id=eventhub_id,
            storage_id=storage_id,
            container_name=container_name
        )

    return tpl

# ---------- Azure ops ----------

def ensure_subscription(sub_id: str | None):
    if sub_id:
        info(f"Setting subscription: {sub_id}")
        az("account", "set", "--subscription", sub_id, fmt=None)
        return sub_id
    sub_id = az("account", "show", "--query", "id")
    info(f"Using active subscription: {sub_id}")
    return sub_id

def get_vm_identity_principal_id(rg: str, vm: str) -> str | None:
    pid = az("vm", "show", "-g", rg, "-n", vm, "--query", "identity.principalId")
    return pid if pid and pid != "None" else None

def assign_system_identity(rg: str, vm: str) -> str:
    info("Assigning system-assigned managed identity to VM...")
    az_json("vm", "identity", "assign", "-g", rg, "-n", vm)
    pid = get_vm_identity_principal_id(rg, vm)
    if not pid:
        raise RuntimeError("Failed to obtain system-assigned MI principalId.")
    info(f"VM system-assigned MI principalId: {pid}")
    return pid

def assign_user_identity(rg: str, vm: str, uai_id: str) -> str:
    info(f"Attaching user-assigned identity to VM: {uai_id}")
    az_json("vm", "identity", "assign", "-g", rg, "-n", vm, "--identities", uai_id)
    pid = get_vm_identity_principal_id(rg, vm)
    if not pid:
        raise RuntimeError("Failed to obtain VM principalId after attaching UAI.")
    info(f"VM principalId (with UAI attached): {pid}")
    return pid

def grant_role(principal_object_id: str, role: str, scope: str):
    info(f"Grant role '{role}' at scope:\n  {scope}")
    az_json(
        "role", "assignment", "create",
        "--assignee-object-id", principal_object_id,
        "--assignee-principal-type", "ServicePrincipal",
        "--role", role,
        "--scope", scope
    )

def ensure_container_exists(storage_id: str, container: str):
    info(f"Ensuring blob container exists: {container}")
    acct = storage_id.split("/storageAccounts/")[-1].split("/")[0]
    try:
        az_json("storage", "container", "create",
                "--name", container,
                "--account-name", acct,
                "--auth-mode", "login")
        info("Container OK.")
    except Exception as e:
        warn(f"Unable to create container automatically (continuing): {e}")

def deploy_template_rg(rg: str, template_obj: dict):
    with tempfile.TemporaryDirectory() as td:
        tf = os.path.join(td, "patched_dcr.json")
        with open(tf, "w", encoding="utf-8") as f:
            json.dump(template_obj, f, indent=2)
        name = f"dcr-deploy-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        info("Deploying patched DCR template...")
        out = az_json("deployment", "group", "create",
                      "-g", rg,
                      "--name", name,
                      "--template-file", tf)
        # Try to pull resource ids
        try:
            outputs = out.get("properties", {}).get("outputResources", [])
            if outputs:
                info("Deployment created/updated resources:")
                for r in outputs:
                    info(f"  - {r.get('id')}")
        except Exception:
            pass

def get_dcr_ids_in_rg(rg: str):
    arr = az_json("resource", "list",
                  "-g", rg,
                  "--resource-type", "Microsoft.Insights/dataCollectionRules",
                  "--query", "[].id")
    return arr or []

def create_dcra_for_vm(sub_id: str, rg: str, vm: str, dcr_id: str):
    dcra_name = f"dcra-{vm}"
    dcra_id = (f"/subscriptions/{sub_id}/resourceGroups/{rg}"
               f"/providers/Microsoft.Compute/virtualMachines/{vm}"
               f"/providers/Microsoft.Insights/dataCollectionRuleAssociations/{dcra_name}")
    info(f"Creating/Upserting DCR Association: {dcra_id}")
    props = {"dataCollectionRuleId": dcr_id, "description": "Associate VM to AgentDirectToStore DCR"}
    az_json("resource", "create",
            "--id", dcra_id,
            "--api-version", "2021-04-01",
            "--properties", json.dumps(props))
    return dcra_id

def install_ama_linux_extension(rg: str, vm: str, version: str, uai_id: str | None, allow_minor_auto_upgrade: bool):
    info(f"Installing AzureMonitorLinuxAgent extension v{version} on VM {vm}...")
    settings = {}
    if uai_id:
        settings = {
            "authentication": {
                "managedIdentity": {
                    "identifier-name": "mi_res_id",
                    "identifier-value": uai_id
                }
            }
        }
    args = [
        "vm", "extension", "set",
        "--resource-group", rg,
        "--vm-name", vm,
        "--publisher", "Microsoft.Azure.Monitor",
        "--name", "AzureMonitorLinuxAgent",
        "--version", version,
        "--settings", json.dumps(settings)
    ]
    if allow_minor_auto_upgrade:
        args += ["--no-auto-upgrade", "false"]  # enable autoUpgradeMinorVersion
    az_json(*args)

    state = az("vm", "extension", "list",
               "--vm-name", vm,
               "--resource-group", rg,
               "--query", "[?name=='AzureMonitorLinuxAgent'].provisioningState | [0]")
    info(f"AMA extension provisioningState: {state}")

# ---------- Main ----------

def main():
    print("=== AMA Direct-to-Store via Exported DCR Template ===")

    # Core inputs
    subscription = prompt("Subscription ID (blank to use current)", default="")
    rg           = prompt("Target Resource Group (DCR + VM)", required=True)
    vm_name      = prompt("Target RHEL VM Name", required=True)

    # DCR overrides
    dcr_name_ovr = prompt("Override DCR name? (blank to keep template)", default="")
    location_ovr = prompt('Override DCR location? (default "centralus", blank keeps template)',
                          default="centralus")
    if location_ovr.lower() == "blank":
        location_ovr = None
    elif not location_ovr:
        location_ovr = "centralus"

    # Destinations
    eventhub_id  = prompt("Event Hub Resource ID (must be the specific event hub)", required=True)
    storage_id   = prompt("Storage Account Resource ID", required=True)
    container    = prompt('Blob container name', default="ama-logs")

    # Identity / agent
    uai_id       = prompt("User Assigned Identity Resource ID (blank for system-assigned)", default="")
    agent_ver    = prompt('AzureMonitorLinuxAgent version', default="1.21")
    auto_minor   = prompt('Enable minor auto-upgrade? (y/n)', default="y").lower().startswith("y")

    # Confirm plan
    plan = {
        "subscription": subscription or "<current>",
        "resourceGroup": rg,
        "vmName": vm_name,
        "dcrNameOverride": dcr_name_ovr or "<keep template>",
        "locationOverride": location_ovr or "<keep template>",
        "eventHubId": eventhub_id,
        "storageId": storage_id,
        "container": container,
        "agentVersion": agent_ver,
        "identityMode": "UserAssigned" if uai_id else "SystemAssigned",
        "autoUpgradeMinorVersion": auto_minor,
        "templateFile": os.path.join(os.getcwd(), TEMPLATE_FILENAME)
    }
    print("\n=== Planned configuration ===")
    print(json.dumps(plan, indent=2))
    if prompt("Proceed? (y/n)", default="y").lower() != "y":
        print("Aborting.")
        sys.exit(0)

    # Subscription
    sub_id = az("account", "show", "--query", "id") if not subscription else None
    sub_id = subscription or sub_id
    ensure_subscription(subscription if subscription else None)

    # Load + patch template
    template_path = os.path.join(os.getcwd(), TEMPLATE_FILENAME)
    if not os.path.isfile(template_path):
        raise SystemExit(f"Template not found: {template_path}")

    patched = load_and_patch_template(
        template_path,
        dcr_name_override=(dcr_name_ovr or None),
        location_override=(location_ovr or None),
        eventhub_id=eventhub_id,
        storage_id=storage_id,
        container_name=container
    )

    # Ensure VM identity
    principal_id = get_vm_identity_principal_id(rg, vm_name)
    if uai_id:
        principal_id = assign_user_identity(rg, vm_name, uai_id)
    else:
        if not principal_id:
            principal_id = assign_system_identity(rg, vm_name)
        else:
            info(f"VM already has system-assigned MI. principalId: {principal_id}")

    # RBAC
    # EH Data Sender
    grant_role(principal_id, "Azure Event Hubs Data Sender", eventhub_id)
    # Storage Blob Data Contributor
    grant_role(principal_id, "Storage Blob Data Contributor", storage_id)

    # Container (best-effort)
    ensure_container_exists(storage_id, container)

    # Deploy DCR
    deploy_template_rg(rg, patched)

    # Resolve a DCR id to associate (pick the most recent by name override if provided, else first in RG)
    dcr_ids = get_dcr_ids_in_rg(rg)
    if not dcr_ids:
        raise RuntimeError("No DCR found after deployment.")
    dcr_id_to_use = None
    if dcr_name_ovr:
        for rid in dcr_ids:
            if rid.endswith(f"/dataCollectionRules/{dcr_name_ovr}"):
                dcr_id_to_use = rid
                break
    if not dcr_id_to_use:
        dcr_id_to_use = dcr_ids[0]
        warn(f"Could not disambiguate DCR by name; using: {dcr_id_to_use}")

    # Associate to VM
    create_dcra_for_vm(sub_id, rg, vm_name, dcr_id_to_use)

    # Install AMA extension
    install_ama_linux_extension(rg, vm_name, agent_ver, uai_id if uai_id else None, allow_minor_auto_upgrade=auto_minor)

    info("Complete. Logs (Syslog + Perf) will flow to Event Hub and Blob per the patched DCR.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        err(str(e))
        sys.exit(1)
