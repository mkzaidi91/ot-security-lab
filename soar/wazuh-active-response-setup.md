# Deploying the OT SOAR playbook on Wazuh

How to wire the Suricata behavioral detection to an automated, OT-safe response
through Wazuh active response. The setup spans two machines: the Wazuh **agent**
on the box closest to the OT (here, the lab host running Suricata and the GRFICS
containers) and the Wazuh **manager** on a separate box.

## Where each piece lives

| Piece | Machine | Path |
| --- | --- | --- |
| Response script | agent | `/var/ossec/active-response/bin/ot_soar_response.py` |
| Case + log output | agent | `/var/ossec/logs/ot-soar/` |
| Rule 100200 | manager | `/var/ossec/etc/rules/local_rules.xml` |
| Command + active-response config | manager | `/var/ossec/etc/ossec.conf` |

## 1. Stage the script on the agent

```bash
sudo cp ot_soar_response.py /var/ossec/active-response/bin/ot_soar_response.py
sudo chown root:wazuh /var/ossec/active-response/bin/ot_soar_response.py
sudo chmod 750 /var/ossec/active-response/bin/ot_soar_response.py
sudo mkdir -p /var/ossec/logs/ot-soar/cases
sudo chown -R wazuh:wazuh /var/ossec/logs/ot-soar
```

Set the `ALLOWLIST` and `PROTECTED_ASSETS` in the script to your real asset
inventory. A write from an allowlisted host (HMI, EWS) is treated as a trusted
host acting out of profile (HIGH). A write from anything else is an unknown or
rogue source (CRITICAL).

Test it in isolation first, writing to a local folder so it needs no privileges:

```bash
echo '{"version":1,"command":"add","parameters":{"alert":{"rule":{"id":"100200"},"data":{"src_ip":"192.168.90.6","dest_ip":"192.168.95.2","alert":{"signature":"OT MODBUS unauthorized write","signature_id":1000010}},"full_log":"test"}}}' \
  | OT_SOAR_DIR=$HOME/ot-soar python3 ot_soar_response.py
cat $HOME/ot-soar/cases/*.json
```

You should get a CRITICAL case. Change the `src_ip` to an allowlisted host and
it drops to HIGH. The `OT_SOAR_DIR` override is for testing only; under Wazuh the
script writes to the default `/var/ossec/logs/ot-soar/`.

## 2. Add the rule on the manager

Add the rule from `local_rules.xml` in this folder. It chains off the built-in
Suricata alert rule (86601) and matches your two behavioral signature IDs.

Two things that will silently stop the rule from firing:

- **Field name.** Suricata's `signature_id` decodes in Wazuh as
  `alert.signature_id`, not `data.alert.signature_id`. Verify the decoded field
  names with the Ruleset Test tool before trusting a rule.
- **Regex flavor.** Wazuh's default field matching is OS_Regex, which does not
  support `[..]` character classes. Use `type="pcre2"` for standard regex.

## 3. Wire the active response on the manager

Add both blocks from `active-response.conf` inside `<ossec_config>` in
`ossec.conf`, then restart the manager. Rule and config changes do not take
effect until the manager restarts.

## 4. Validate, then test end to end

- **Validate the rule** with the Ruleset Test tool: paste a real Suricata alert
  line from `eve.json` and confirm it matches rule 100200 at level 12.
- **Test the full chain**: send one unauthorized Modbus write at the PLC, then
  check for a fresh case:

```bash
sudo ls -lt /var/ossec/logs/ot-soar/cases/
```

A new case file owned by `root:wazuh`, created seconds after the write, means
the whole pipeline fired on its own: Suricata to Wazuh rule to active response
to playbook.

## OT-safety design

The response never touches the PLC, the control network, or the running process.
Automated actions are limited to opening a case, enriching it, notifying on-call,
and logging. Any disruptive containment is staged as a recommendation for a human
analyst to approve, and only at the IT/DMZ boundary (Purdue Level 3.5). In OT,
availability and safety outrank confidentiality, so an automated response that
can trip a live process is unacceptable.
