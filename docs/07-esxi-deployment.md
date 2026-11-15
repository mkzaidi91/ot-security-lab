# 07 — Deploying on VMware ESXi (with self-hosted Wazuh SIEM)

Rebuilding the GRFICSv3 lab on a VMware ESXi host (migrated from Proxmox),
forwarding the Suricata detections into a self-hosted Wazuh SIEM, and making
the whole pipeline persistent with systemd.

## Architecture

```
Kali (DMZ) --unauthenticated Modbus write--> PLC (ICS)
   -> Suricata (detection, writes eve.json)
      -> Wazuh agent (reads eve.json)
         -> Wazuh manager / dashboard
```

- **Host:** VMware ESXi 8
- **Lab VM:** Ubuntu 22.04 Server running the GRFICSv3 Docker stack
- **SIEM:** a separate Ubuntu VM running a single-node Wazuh deployment

## 1. ESXi macvlan requirement (critical)

GRFICSv3 uses Docker **macvlan** networks, which assign multiple MAC addresses
from one VM NIC. ESXi blocks this by default. On the port group the lab VM uses,
set the Security policy to **Accept** for all three:

- Promiscuous mode: Accept
- MAC address changes: Accept
- Forged transmits: Accept

Without this, the macvlan containers cannot communicate.

## 2. NIC parent interface

The macvlan networks reference a `parent:` interface in `docker-compose.yml`.
Set it to the lab VM's NIC (find with `ip -br link` — on an ESXi VMXNET3 adapter
it is typically `ens34`):

```
sed -i 's/parent: <old>/parent: <your-nic>/g' docker-compose.yml
```

## 3. Monitoring macvlan traffic with Suricata (network namespace)

Because the lab networks are macvlan, the host NIC cannot see the inter-zone
traffic — it is switched inside Docker. The cross-zone traffic (DMZ -> ICS,
including the attack) is forwarded by the GRFICS `router` container, so Suricata
must watch **inside the router's network namespace**.

The router's ICS-facing interface is `eth2` (the `192.168.95.x` side). Run the
host-installed Suricata inside the router's netns with `nsenter` — the filesystem
stays the host's, so `eve.json` still lands at `/var/log/suricata/` where the
Wazuh agent reads it:

```
PID=$(docker inspect -f '{{.State.Pid}}' router)
sudo nsenter -t "$PID" -n suricata -i eth2 -c /etc/suricata/suricata.yaml -l /var/log/suricata
```

Custom OT rules live in `detections/ot-modbus.rules` (copied to
`/etc/suricata/rules/`) and are loaded via `rule-files` in `suricata.yaml`.

## 4. Forwarding Suricata alerts to Wazuh

The Wazuh agent on the lab VM reads Suricata's JSON output. In
`/var/ossec/etc/ossec.conf`:

```
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

Wazuh ships built-in Suricata decoders, so alerts are parsed and appear in the
dashboard (rule.id `86601`, agent `otlab`).

## 5. Persistence (systemd)

Two units in `deploy/` make the lab self-starting and reboot-safe:

- `grfics.service` — runs `docker compose up -d` on boot so the whole lab comes up.
- `ot-suricata.service` — runs `deploy/ot-suricata.sh`, which waits for the
  `router` container, resolves its PID, and launches Suricata in its netns;
  restarts on failure.

Install:

```
sudo cp deploy/ot-suricata.sh /usr/local/bin/ && sudo chmod +x /usr/local/bin/ot-suricata.sh
sudo cp deploy/ot-suricata.service deploy/grfics.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now grfics.service ot-suricata.service
```

## 6. Validation

```
docker exec kali python3 -c "from pymodbus.client import ModbusTcpClient; c=ModbusTcpClient('192.168.95.2',port=502); c.connect(); c.write_register(1,60000); c.close()"
sudo tail -n 8 /var/log/suricata/fast.log
```

All four OT rules fire (see `detections/sample-alerts.log`), and the alert
appears in the Wazuh dashboard under agent `otlab`.
