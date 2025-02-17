# xtables-addons with `xt_XTEE` target

Replicates the legacy `ipt_ROUTE` target.

## Usage example

Forward traffic from an untagged client (based on MAC-address) into a bridge as if the packets were appropriately VLAN-tagged:
```
*mangle

-A PREROUTING -i eth0 -m mac --mac-source AA:BB:CC:DD:EE:FF -j TTL --ttl-inc 1
-A PREROUTING -i eth0 -m mac --mac-source AA:BB:CC:DD:EE:FF -j XTEE --iif br0
```
