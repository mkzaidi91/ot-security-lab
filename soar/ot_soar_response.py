#!/usr/bin/env python3
"""
ot_soar_response.py  -  OT-safe SOAR playbook for Wazuh Active Response

Trigger:   fires when Wazuh rule 100200 matches (an unauthorized Modbus write
           detected by the Suricata behavioral rules sid 1000010 / 1000011,
           i.e. a write to the PLC from a source that is NOT the HMI or EWS).

OT-safe by design: it opens a case, enriches, notifies, and logs. It NEVER
touches the PLC or the live process, and it does NOT auto-block. Any disruptive
action is staged as a recommendation a human analyst must approve.

Dependencies: Python 3 standard library only.
"""

import sys
import os
import json
import socket
import ipaddress
import urllib.request
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# CONFIG  -  your GRFICS lab (Dallas otlab)
# --------------------------------------------------------------------------

# Legitimate Modbus writers to the PLC. A write from any of these is a trusted
# device acting out of profile (still suspicious). Anything else is unknown/rogue.
ALLOWLIST = {
    "192.168.90.107": "HMI (ScadaBR operator station)",
    "192.168.95.5": "EWS (engineering workstation)",
}

# The PLC / protected asset(s). Used only to describe the target, never acted on.
PROTECTED_ASSETS = {
    "192.168.95.2": "OpenPLC controller (Modbus/TCP 502)",
}

# Where cases and logs are written. Defaults to the Wazuh path; override with
# the OT_SOAR_DIR env var for local testing (e.g. OT_SOAR_DIR=$HOME/ot-soar).
BASE_DIR = os.environ.get("OT_SOAR_DIR", "/var/ossec/logs/ot-soar")
CASE_DIR = os.path.join(BASE_DIR, "cases")
LOG_FILE = os.path.join(BASE_DIR, "ot_soar.log")

# Optional webhook. Set env var WEBHOOK_URL, or leave empty to skip notification.
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")

# --------------------------------------------------------------------------


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg):
    try:
        os.makedirs(BASE_DIR, exist_ok=True)
        with open(LOG_FILE, "a") as fh:
            fh.write("{} {}\n".format(now_iso(), msg))
    except Exception:
        pass


def read_ar_input():
    try:
        raw = sys.stdin.readline()
        if not raw:
            return None, None
        data = json.loads(raw)
        command = data.get("command")
        alert = data.get("parameters", {}).get("alert", {})
        return command, alert
    except Exception as exc:
        log("ERROR could not parse AR stdin: {}".format(exc))
        return None, None


def dig(d, *path, default=None):
    cur = d
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return cur


def extract_event(alert):
    data = alert.get("data", {})
    src_ip = (dig(data, "src_ip")
              or dig(data, "srcip")
              or dig(alert, "data", "alert", "source", "ip"))
    dest_ip = (dig(data, "dest_ip")
               or dig(data, "dstip")
               or dig(alert, "data", "alert", "target", "ip"))
    signature = dig(data, "alert", "signature", default="(no signature)")
    signature_id = dig(data, "alert", "signature_id")
    return {
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "signature": signature,
        "signature_id": signature_id,
        "wazuh_rule": dig(alert, "rule", "id"),
        "wazuh_desc": dig(alert, "rule", "description"),
        "full_log": alert.get("full_log", ""),
    }


def enrich(event):
    src = event["src_ip"]
    dest = event["dest_ip"]
    src_label = ALLOWLIST.get(src)
    dest_label = PROTECTED_ASSETS.get(dest, dest)

    if src_label:
        classification = "trusted_host_anomaly"
        severity = "HIGH"
        src_desc = "{} ({})".format(src, src_label)
        recommended = (
            "Investigate the known host {}: confirm whether the write was "
            "operator-initiated or spoofed. Do NOT block the control host. "
            "Pull its recent session and command history.".format(src)
        )
    else:
        classification = "unknown_source_write"
        severity = "CRITICAL"
        src_desc = "{} (NOT in control-system inventory)".format(src)
        recommended = (
            "Unknown host {} is issuing Modbus writes to the PLC. Recommended "
            "containment: block {} at the IT/DMZ boundary firewall (Level 3.5), "
            "NOT inside the control network, and NOT on the PLC. "
            "ANALYST APPROVAL REQUIRED before any block is applied so the live "
            "process is never disrupted.".format(src, src)
        )

    return {
        "classification": classification,
        "severity": severity,
        "src_desc": src_desc,
        "dest_desc": dest_label,
        "recommended_action": recommended,
    }


def build_case(event, context):
    case_id = "{}-{}".format(
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S"),
        (event["src_ip"] or "unknown").replace(".", "_"),
    )
    case = {
        "case_id": case_id,
        "created": now_iso(),
        "status": "OPEN_PENDING_ANALYST_APPROVAL",
        "detection": {
            "source_ip": event["src_ip"],
            "source_assessment": context["src_desc"],
            "target": context["dest_desc"],
            "suricata_signature": event["signature"],
            "suricata_sid": event["signature_id"],
            "wazuh_rule": event["wazuh_rule"],
        },
        "triage": {
            "classification": context["classification"],
            "severity": context["severity"],
            "mitre_attack_ics": "T0836 Modify Parameter / unauthorized command message",
        },
        "response": {
            "automated_actions_taken": [
                "Opened incident case (this file)",
                "Sent enriched notification to on-call webhook",
                "Logged playbook execution for audit",
            ],
            "recommended_action_pending_approval": context["recommended_action"],
            "ot_safety_note": (
                "No automated action touched the PLC, the control network, or "
                "the running process. Disruptive containment is staged for human "
                "approval only."
            ),
        },
        "raw_full_log": event["full_log"],
    }
    return case_id, case


def write_case(case_id, case):
    try:
        os.makedirs(CASE_DIR, exist_ok=True)
        path = os.path.join(CASE_DIR, case_id + ".json")
        with open(path, "w") as fh:
            json.dump(case, fh, indent=2)
        log("CASE written {}".format(path))
        return path
    except Exception as exc:
        log("ERROR writing case: {}".format(exc))
        return None


def notify(case):
    if not WEBHOOK_URL:
        log("NOTIFY skipped (no WEBHOOK_URL set)")
        return
    det = case["detection"]
    tri = case["triage"]
    text = (
        "[OT SOC] {sev} - {cls}\n"
        "Source: {src}\n"
        "Target: {tgt}\n"
        "Signature: {sig}\n"
        "Case: {cid} (status: {st})\n"
        "Recommended (needs analyst approval): {rec}"
    ).format(
        sev=tri["severity"],
        cls=tri["classification"],
        src=det["source_assessment"],
        tgt=det["target"],
        sig=det["suricata_signature"],
        cid=case["case_id"],
        st=case["status"],
        rec=case["response"]["recommended_action_pending_approval"],
    )
    payload = json.dumps({"text": text}).encode("utf-8")
    try:
        req = urllib.request.Request(
            WEBHOOK_URL, data=payload,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=5)
        log("NOTIFY sent for case {}".format(case["case_id"]))
    except Exception as exc:
        log("ERROR webhook failed: {}".format(exc))


def main():
    command, alert = read_ar_input()
    if command != "add":
        return
    if not alert:
        log("ERROR empty alert, nothing to do")
        return
    event = extract_event(alert)
    context = enrich(event)
    case_id, case = build_case(event, context)
    write_case(case_id, case)
    notify(case)
    log("PLAYBOOK complete case={} severity={} src={}".format(
        case_id, context["severity"], event["src_ip"]))


if __name__ == "__main__":
    main()
