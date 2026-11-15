#!/usr/bin/env bash
set -e
CID=router
# wait until the router container is running
until [ "$(docker inspect -f '{{.State.Running}}' "$CID" 2>/dev/null)" = "true" ]; do
  sleep 2
done
PID=$(docker inspect -f '{{.State.Pid}}' "$CID")
rm -f /var/run/suricata.pid
exec nsenter -t "$PID" -n suricata -i eth2 -c /etc/suricata/suricata.yaml -l /var/log/suricata
