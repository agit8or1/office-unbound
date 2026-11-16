# Proxmox SDN isolation for two customers (owner commands, NOT yet applied)

Target: pve06 (PVE 9.2), one Simple SDN zone, one VNet per customer, default-DROP between customers. Design and reasoning: [fullstack-readiness.md](../status/fullstack-readiness.md) section 3. Test plan once applied: [network-isolation-test-plan.md](../status/network-isolation-test-plan.md).
**Run these as root on pve06, by the infrastructure owner.** They have not been run by anyone; syntax follows the PVE 9 API but was only checked against a read-only API (`pvesh usage` pre-flight in section 0 catches differences before anything changes). Never paste a token secret anywhere.

## 0. Read before running
* SDN zones, VNets and the firewall **datacenter** objects are cluster-wide (`/etc/pve`). Everything below limits effect to pve06: the zone has `--nodes pve06`; datacenter firewall policies are set to ACCEPT so enabling the firewall service does not start filtering the other five nodes; only pve06 gets `nftables 1` and a node firewall.
* Decision needed: enabling the datacenter firewall (`enable 1`) starts the firewall daemon cluster-wide. With the ACCEPT policies below its behaviour on other nodes is unchanged, but if any other node already has node-level rules they become active. Check first (section 1 prints them). If you refuse a cluster-wide switch, stop here; the alternative is VM-level firewall rules per VM, which the ICS cannot create yet.
* Fill in the variables in section 1 first. The script stops if one is empty.
* Rule creation order: the PVE API may insert new rules at the top or append them; section 3 detects which and builds the lists accordingly, and section 3 ends with an order check that must print `ORDER OK`.

## 1. Variables and pre-flight (read-only)
```sh
# --- fill in ---
ICS_IP=192.168.22.167           # ICS host (agent client, callback listener)
CALLBACK_PORT=8445              # ICS_GUEST_CALLBACK_URL port (dedicated serve_callback behind TLS)
REPO_IPS="CHANGE_ME"            # signed apt repo / OCI registry host(s), space separated; the ICS host if it serves them
REPO_PORT=443
BACKUP_IPS="CHANGE_ME"          # backup target (restic repository host), NOT on PVE06-Storage
BACKUP_PORT=8000
DNS_IPS="192.168.22.1"          # resolvers guests use (also given to the ICS plan)
NTP_IPS="192.168.22.1"
EDGE_IPS="CHANGE_ME"            # reverse proxy / port-forward hosts allowed to reach customer service ports
ZONE=oucust
NODE=pve06
# customers: <vnet>:<subnet>:<gateway>:<label>
CUSTOMERS="ouc01:10.64.1.0/24:10.64.1.1:customer-a ouc02:10.64.2.0/24:10.64.2.1:customer-b"
# ---------------
for v in ICS_IP REPO_IPS BACKUP_IPS EDGE_IPS; do eval "[ -n \"\$$v\" ] && [ \"\$$v\" != CHANGE_ME ]" || { echo "set $v"; return 1 2>/dev/null || exit 1; }; done
pveversion; pvesh get /cluster/sdn/zones; pvesh get /cluster/sdn/vnets            # expect: empty
pvesh get /cluster/firewall/options; pvesh get /nodes/$NODE/firewall/options      # note current state, keep it for the undo section
for n in $(pvesh get /nodes --noborder -o json | python3 -c 'import sys,json;print(*[x["node"] for x in json.load(sys.stdin)])'); do echo "== $n"; pvesh get /nodes/$n/firewall/rules --noborder; done
sysctl net.ipv4.ip_forward                                                        # needs to be 1 on pve06 (section 2)
# the VNet firewall API must exist on this version, else STOP:
pvesh usage /cluster/sdn/vnets/ouc01/firewall/options --command set >/dev/null 2>&1 && echo "vnet firewall API present" || echo "MISSING: vnet firewall API"
pvesh usage /cluster/sdn/zones --command create | grep -E 'nodes|zone|type' | head
```

## 2. SDN zone, VNets, subnets (idempotent)
```sh
pvesh get /cluster/sdn/zones/$ZONE >/dev/null 2>&1 || pvesh create /cluster/sdn/zones --zone $ZONE --type simple --nodes $NODE --ipam pve
for c in $CUSTOMERS; do IFS=: read V S G L <<<"$c"
  pvesh get /cluster/sdn/vnets/$V >/dev/null 2>&1 || pvesh create /cluster/sdn/vnets --vnet $V --zone $ZONE --alias "$L"
  pvesh get /cluster/sdn/vnets/$V/subnets --noborder | grep -q "$S" || \
    pvesh create /cluster/sdn/vnets/$V/subnets --type subnet --subnet $S --gateway $G --snat 0
done
pvesh set /cluster/sdn                                   # apply (reloads networking for the zone's nodes only: pve06)
# routing: the node must forward between the ICS LAN and the VNets (never between VNets: the VNet firewall drops that)
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/90-ou-sdn.conf && sysctl --system | grep ip_forward
```
Verify:
```sh
pvesh get /cluster/sdn/zones; pvesh get /cluster/sdn/vnets; ip -br addr show | grep -E 'ouc0'
```
Expected: zone `oucust` (simple, nodes pve06), VNets `ouc01`, `ouc02`, interfaces `ouc01` 10.64.1.1/24 and `ouc02` 10.64.2.1/24 UP.

## 3. Firewall objects and rules
### 3.1 IP sets and aliases (cluster-wide, harmless: they only name addresses)
```sh
mkset() { pvesh get /cluster/firewall/ipset/$1 >/dev/null 2>&1 || pvesh create /cluster/firewall/ipset --name $1 --comment "$2"; shift 2
          for a in "$@"; do pvesh get /cluster/firewall/ipset/$SET --noborder 2>/dev/null | grep -qw "$a" || pvesh create /cluster/firewall/ipset/$SET --cidr $a; done; }
SET=ou_ics;    mkset $SET "Office Unbound ICS" $ICS_IP
SET=ou_repo;   mkset $SET "signed apt repo / registry" $REPO_IPS
SET=ou_backup; mkset $SET "backup target" $BACKUP_IPS
SET=ou_dns;    mkset $SET "resolvers" $DNS_IPS
SET=ou_ntp;    mkset $SET "time servers" $NTP_IPS
SET=ou_edge;   mkset $SET "edge / reverse proxy" $EDGE_IPS
SET=ou_private; mkset $SET "RFC1918 (everything private that is not explicitly allowed above)" 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
SET=ou_cust;   mkset $SET "all customer subnets" 10.64.0.0/16
```
### 3.2 Datacenter and node switches (the cluster-wide step; read section 0)
```sh
pvesh set /cluster/firewall/options --enable 1 --policy_in ACCEPT --policy_out ACCEPT --policy_forward ACCEPT
pvesh set /nodes/$NODE/firewall/options --enable 1 --nftables 1
```
### 3.3 Rules (pve06 node: guests -> host) and VNet forward rules
Creates each list in the order written (first rule = evaluated first). The helper probes the API insertion order once with a throw-away group, then applies.
```sh
# probe: does POST append (new rule last) or prepend (new rule first)?
pvesh create /cluster/firewall/groups --group ou-probe >/dev/null
pvesh create /cluster/firewall/groups/ou-probe --type in --action ACCEPT --comment first >/dev/null
pvesh create /cluster/firewall/groups/ou-probe --type in --action DROP --comment second >/dev/null
FIRSTCOMMENT=$(pvesh get /cluster/firewall/groups/ou-probe --noborder -o json | python3 -c 'import sys,json;r=json.load(sys.stdin);print(sorted(r,key=lambda x:x["pos"])[0]["comment"])')
pvesh delete /cluster/firewall/groups/ou-probe/1 >/dev/null; pvesh delete /cluster/firewall/groups/ou-probe/0 >/dev/null; pvesh delete /cluster/firewall/groups/ou-probe
[ "$FIRSTCOMMENT" = first ] && ORDER=append || ORDER=prepend; echo "API insertion: $ORDER"

reset_rules() { for p in $(pvesh get "$1" --noborder -o json | python3 -c 'import sys,json;print(*sorted([r["pos"] for r in json.load(sys.stdin)],reverse=True))'); do pvesh delete "$1/$p" >/dev/null; done; }
# apply_rules <rules path> <file with one rule per line: pvesh create args>
apply_rules() { reset_rules "$1"; if [ $ORDER = append ]; then cat "$2"; else tac "$2"; fi | while read -r line; do eval "pvesh create $1 $line" >/dev/null; done; }
```
Node rules (guests cannot reach the host itself; one drop per VNet interface):
```sh
: > /tmp/ou-node.rules
for c in $CUSTOMERS; do IFS=: read V S G L <<<"$c"; echo "--type in --iface $V --action DROP --comment ou-guest-to-host-$V" >> /tmp/ou-node.rules; done
apply_rules /nodes/$NODE/firewall/rules /tmp/ou-node.rules
```
VNet rules (per customer; `$S` = its subnet). Allow-list first, explicit drops last:
```sh
for c in $CUSTOMERS; do IFS=: read V S G L <<<"$c"
R=/tmp/ou-$V.rules; : > $R
add() { echo "--type forward --action $1 $2 --comment $3" >> $R; }
add ACCEPT "--proto tcp --dport 8443 --source +ou_ics --dest $S"                 mgmt-agent
add ACCEPT "--proto tcp --dport $CALLBACK_PORT --source $S --dest +ou_ics"       bootstrap-callback
add ACCEPT "--proto tcp --dport $REPO_PORT --source $S --dest +ou_repo"          repo
add ACCEPT "--proto tcp --dport $BACKUP_PORT --source $S --dest +ou_backup"      backup
add ACCEPT "--proto udp --dport 53 --source $S --dest +ou_dns"                   dns-udp
add ACCEPT "--proto tcp --dport 53 --source $S --dest +ou_dns"                   dns-tcp
add ACCEPT "--proto udp --dport 123 --source $S --dest +ou_ntp"                  ntp
add ACCEPT "--proto tcp --dport 25,80,443,587,993,5061,8089 --source +ou_edge --dest $S" edge-in-tcp
add ACCEPT "--proto udp --dport 10000:10200 --source +ou_edge --dest $S"         edge-in-media
add ACCEPT "--source $S --dest $S"                                              intra-customer
add DROP   "--source $S --dest +ou_cust"                                        deny-other-customers
add DROP   "--source +ou_cust --dest $S"                                        deny-from-other-customers
add DROP   "--source $S --dest +ou_private"                                     deny-lan
add DROP   ""                                                                   default-drop
apply_rules /cluster/sdn/vnets/$V/firewall/rules $R
pvesh set /cluster/sdn/vnets/$V/firewall/options --enable 1 --policy_forward DROP
done
```
Note: `intra-customer` accepts all traffic between the customer's own VMs at the hypervisor; per-port filtering inside the customer is the guests' nftables (defence in depth, not counted as isolation). The `deny-other-customers` rules come after `intra-customer` and only match foreign subnets because `intra-customer` already took the own subnet.
Order check (must print `ORDER OK` for every VNet, else re-run section 3.3 and send the output to the lead):
```sh
for c in $CUSTOMERS; do IFS=: read V S G L <<<"$c"
  pvesh get /cluster/sdn/vnets/$V/firewall/rules --noborder -o json | python3 -c '
import sys,json
r=sorted(json.load(sys.stdin),key=lambda x:x["pos"]); c=[x["comment"] for x in r]
want=["mgmt-agent","bootstrap-callback","repo","backup","dns-udp","dns-tcp","ntp","edge-in-tcp","edge-in-media","intra-customer","deny-other-customers","deny-from-other-customers","deny-lan","default-drop"]
print("ORDER OK" if c==want else "ORDER WRONG: %s"%c)'; done
```

## 4. Proxmox grants for the ICS token (least privilege; no `SDN.Allocate`)
The token `officeunbound@pam!ics` is privilege-separated: grant to the user **and** the token. `PVESDNUser` = `SDN.Use` + `SDN.Audit`; it does **not** allow creating or changing SDN objects. Check first: `pveum role list | grep -i sdn`.
```sh
for c in $CUSTOMERS; do IFS=: read V S G L <<<"$c"
  pveum acl modify /sdn/zones/$ZONE/$V --users officeunbound@pam --roles PVESDNUser
  pveum acl modify /sdn/zones/$ZONE/$V --tokens 'officeunbound@pam!ics' --roles PVESDNUser
done
# optional read access so the ICS can inventory VNets later (read only):
pveum acl modify /sdn/zones/$ZONE --tokens 'officeunbound@pam!ics' --roles PVESDNUser   # includes SDN.Audit on the zone and its VNets
# once VNets work and the first plan is accepted, remove the shared bridge so no plan can use it:
# pveum acl delete /sdn/zones/localnetwork/vmbr0 --tokens 'officeunbound@pam!ics' --roles PVESDNUser
# pveum acl delete /sdn/zones/localnetwork/vmbr0 --users officeunbound@pam --roles PVESDNUser
```
Do **not** grant `SDN.Allocate`, `Sys.Modify`, `Permissions.Modify`, `VM.Console`, or any right on `/sdn` itself. The existing `VM.Config.Network` in role `OfficeUnboundDeploy` is what lets the ICS attach a NIC; it can attach only to a VNet where it also holds `SDN.Use`.
**Optional strict variant** (Proxmox itself refuses cross-customer attach): one pool and one token per customer, e.g. pool `ou-cust-a` with token `officeunbound@pam!ics-a` holding `OfficeUnboundDeploy` on `/pool/ou-cust-a`, `PVEDatastoreUser` on `/storage/PVE06-Storage` and `PVESDNUser` on **only** `/sdn/zones/oucust/ouc01`; same for customer B with `ouc02`; register two ICS endpoints, each with `allowed_networks = [its VNet]`. Cost: two endpoints and two secrets to rotate.
Verify:
```sh
pveum user token permissions officeunbound@pam ics --path /sdn/zones/oucust/ouc01
pveum user token permissions officeunbound@pam ics --path /sdn/zones/oucust/ouc02
pveum user token permissions officeunbound@pam ics --path /sdn      # expect: nothing, or SDN.Audit at most
```

## 5. ICS side (not owner commands, listed for the sequence)
1. ICS host: `ip route add 10.64.0.0/16 via 192.168.22.17` (persist via netplan; record in `docs/status/host-changes.md`). Guests answer ICS-initiated flows through the same path (no NAT, `--snat 0`).
2. Write the network model file named by `OU_NETWORK_MODEL` (assignments `customer-a -> ouc01 10.64.1.0/24`, `customer-b -> ouc02 10.64.2.0/24`, `flows` with the same addresses used above) and add each VNet to the endpoint's allowed networks. Plans then bind each customer to its VNet and list the flows.

## 6. Global verification (after sections 2-4)
```sh
pvesh get /cluster/firewall/options; pvesh get /nodes/$NODE/firewall/options
for c in $CUSTOMERS; do IFS=: read V S G L <<<"$c"; pvesh get /cluster/sdn/vnets/$V/firewall/options; done   # enable 1, policy_forward DROP
nft list ruleset | grep -c ouc0            # rules are present in the nftables ruleset (proxmox-firewall)
```
Then run the test plan. Do not create customer VMs before the negative tests pass on two throw-away VMs.

## 7. Undo (restores the state read in section 1)
```sh
for c in $CUSTOMERS; do IFS=: read V S G L <<<"$c"
  pvesh set /cluster/sdn/vnets/$V/firewall/options --enable 0
  reset_rules /cluster/sdn/vnets/$V/firewall/rules
done
reset_rules /nodes/$NODE/firewall/rules
pvesh set /nodes/$NODE/firewall/options --enable 0 --delete nftables
# datacenter firewall: set back to the values printed in section 1 ("pvesh get /cluster/firewall/options"); if it was empty/disabled:
pvesh set /cluster/firewall/options --delete enable,policy_in,policy_out,policy_forward
for s in ou_ics ou_repo ou_backup ou_dns ou_ntp ou_edge ou_private ou_cust; do
  for a in $(pvesh get /cluster/firewall/ipset/$s --noborder -o json | python3 -c 'import sys,json;print(*[x["cidr"] for x in json.load(sys.stdin)])'); do pvesh delete /cluster/firewall/ipset/$s/${a//\//%2F}; done
  pvesh delete /cluster/firewall/ipset/$s
done
# ONLY with no VM attached to the VNets:
for c in $CUSTOMERS; do IFS=: read V S G L <<<"$c"; pvesh delete /cluster/sdn/vnets/$V/subnets/$ZONE-${S/\//-}; pvesh delete /cluster/sdn/vnets/$V; done
pvesh delete /cluster/sdn/zones/$ZONE; pvesh set /cluster/sdn
rm -f /etc/sysctl.d/90-ou-sdn.conf
# grants
for c in $CUSTOMERS; do IFS=: read V S G L <<<"$c"
  pveum acl delete /sdn/zones/$ZONE/$V --tokens 'officeunbound@pam!ics' --roles PVESDNUser
  pveum acl delete /sdn/zones/$ZONE/$V --users officeunbound@pam --roles PVESDNUser
done
pveum acl delete /sdn/zones/$ZONE --tokens 'officeunbound@pam!ics' --roles PVESDNUser
```
Subnet ids in the delete line follow `<zone>-<network>-<prefix>`; confirm with `pvesh get /cluster/sdn/vnets/<vnet>/subnets` before deleting.
