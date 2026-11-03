# Traffic Baseline

## Normal Modbus/TCP behavior
- The PLC (192.168.95.2) is the only Modbus client (master).
- It polls remote I/O devices at 192.168.95.10-.15 on TCP port 502.
- Traffic is continuous, cyclic read requests and responses
  (~12-15 byte payloads), several times per second.
- No other host initiates Modbus. No write functions seen in normal polling.

## Why this matters for detection
OT traffic is highly predictable. A reliable detection strategy is to
alert on anything that breaks this baseline:
- A Modbus client that is NOT the PLC
- Modbus write function codes (the PLC normally reads)
- Modbus traffic crossing from the DMZ into the ICS network
