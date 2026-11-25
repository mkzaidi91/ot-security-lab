# SIEM Integration: Suricata to Wazuh

## Approach
The Suricata sensor on the ICS network writes alerts to `eve.json`. A Wazuh
agent on the OT lab host ships those alerts to a central Wazuh manager
(192.168.1.176), which decodes them, raises SIEM alerts, and presents them in the
dashboard. This moves the OT network detections off the sensor and into one place
where they can be correlated, tracked, and acted on, the way a real OT SOC works.

## Agent configuration
The Wazuh agent reads Suricata's `eve.json` as a JSON log source, so every alert
event is parsed into fields the manager can match rules against. The agent and
manager versions must match (the manager runs the single-node Docker compose at
v4.14.7), or the agent will not report cleanly.

## Decoding and elevation
Wazuh's built-in Suricata ruleset decodes each alert and fires rule **86601**
(Suricata: Alert) at level 3. On its own that leaves the OT Modbus-write alerts
sitting in the low-severity noise with everything else.

A custom local rule, **100200** (level 12), chains off 86601 and matches only the
OT behavioral signatures (Suricata sid 1000010 and 1000011). It promotes those
specific alerts to high severity so they stand out in the dashboard and can
trigger an automated response. See [`../soar/local_rules.xml`](../soar/local_rules.xml).

## Field-name and regex gotchas
Two things silently stopped rule 100200 from matching until I tracked them down
with the Ruleset Test tool:

- Suricata's `signature_id` decodes in Wazuh as `alert.signature_id`, not the
  `data.alert.signature_id` I first assumed. The Ruleset Test output shows the
  real decoded field names, which is the fastest way to confirm this.
- Wazuh field matching defaults to its own regex flavor (OS_Regex), which does
  not support `[..]` character classes. Matching `^100001[01]$` required setting
  `type="pcre2"` on the field.

## Result
Both OT attack alerts reach the manager and appear in the dashboard, source IP
and MITRE ATT&CK for ICS mapping intact. With rule 100200 in place, the Modbus
write from the DMZ shows as a high-severity event rather than a low one.

Full pipeline: Kali (DMZ) -> PLC -> Suricata (ICS sensor) -> Wazuh agent ->
Wazuh manager, tagged with MITRE ATT&CK for ICS T0836 and T0855.

## Next step
Rule 100200 is also the trigger for the automated response. An active response
on the agent runs a Python SOAR playbook that triages the alert and opens an
incident case, without ever touching the live process. See [`../soar/`](../soar/).
