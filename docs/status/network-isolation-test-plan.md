# Two-customer network isolation test plan (agent BY) -- Status: Planned, not executed

Run only after the owner has applied `docs/admin/proxmox-sdn-isolation.md` sections 1-4 and the ICS host route exists. Pass criterion for the release (tenant-isolation-results.md follow-up 1): **every NEG test shows the connection blocked, every POS test shows it open, and the paired control proves the probe itself works.** Any NEG that connects is a release blocker.

## Rules of engagement
* Probes originate **inside guests** through signed agent runbooks (typed `guest.runbook` actions via the ICS, two-approver plan like any other action); no ssh, no shell API. If a connectivity probe runbook does not exist yet, it is a closed-shape runbook `net.probe {proto, host, port, timeout}` that does a single TCP connect / UDP send+nothing / `ping -c1` and returns only `open|closed|filtered` + elapsed ms (to be added to `ics/agent/deploy/runbooks/`, with fixed argument validation: the destination must be a literal address inside the **own customer subnet or an address in the plan's `network.flows`**; it can therefore not be used to scan).
* **No scanning outside the customer subnets**: only the specific (address, port) pairs listed below, one connection each, from the specific guest listed. No port sweeps, no ranges except the media range test (single UDP datagram to 3 ports). Nothing is sent to pve01-05, ha-zfs, PBS1, VM 126 or other LAN hosts except the allow-listed ICS/repo/DNS/NTP/backup/edge addresses.
* Use throw-away test VMs first (two small VMs per customer from the golden image: `a-t1`, `a-t2`, `b-t1`, `b-t2`), then repeat the same table on the real stacks. Test VMs are created by the ICS in the customer's own VNet like any deployment, and destroyed afterwards.
* Addresses (example, from the network model): A = `10.64.1.0/24` (VNet `ouc01`), B = `10.64.2.0/24` (`ouc02`), gateways `.1`, ICS = `192.168.22.167`, node = `192.168.22.17`.
* Record every result row as: id, source guest, target, observed, expected, PASS/FAIL, plus the raw runbook output in `docs/status/network-isolation-evidence/` (created at execution time).

## A. Positive flows (must be open)
| ID | From | To | Proto/port | Why |
|---|---|---|---|---|
| P01 | ICS (host, `curl --cacert` via agent client) | a-t1:8443 and b-t1:8443 | tcp | agent control path, mTLS handshake succeeds |
| P02 | a-t1 | ICS callback `ICS_IP:CALLBACK_PORT` | tcp | bootstrap callback (HTTPS /healthz only; pinned certificate) |
| P03 | a-t1, b-t1 | repo/registry host:443 | tcp | signed apt/registry reachable (apt update succeeds) |
| P04 | a-t1, b-t1 | backup target:PORT | tcp | restic repository reachable |
| P05 | a-t1, b-t1 | resolver:53 | udp + tcp | DNS resolves the customer FQDN and the repo name |
| P06 | a-t1, b-t1 | NTP:123 | udp | time sync (chrony `tracking` shows a source) |
| P07 | edge host | a-t1 (and a real `id` VM): 443, 25, 587, 993 | tcp | published service ports from the edge ipset only |
| P08 | edge host | a-pbx: udp 10000 (one datagram), tcp 5061, 8089 | udp/tcp | telephony/meetings ports |
| P09 | a-t1 | a-t2 (any port the plan allows, and ICMP) | tcp/icmp | intra-customer traffic works (so isolation is not "everything is broken") |
| P10 | a-t1 | gateway `10.64.1.1` ICMP | icmp | routing path alive (control for later negatives) |

## B. Negative flows (must be blocked)
| ID | From | To | Proto/port | Expectation |
|---|---|---|---|---|
| N01 | a-t1 | b-t1 on one specific port each: 22, 8443, 443 (3 single connects) | tcp | filtered/timeout; paired control P09 and P01 pass in the same run |
| N02 | b-t1 | a-t1 on 22, 8443, 443 | tcp | filtered |
| N03 | a-t1 | b-t1 ICMP echo | icmp | no reply |
| N04 | a-t1 | b-t1 ARP/L2: `arping -c1 <B ip>` | l2 | no reply (separate bridges; proves L2 separation, not only L3) |
| N05 | a-t1 | B gateway `10.64.2.1` ICMP | icmp | no reply (cannot even reach the other VNet's router address) |
| N06 | a-t1 | node `192.168.22.17`: 22 and 8006 (2 connects) | tcp | filtered (node `in DROP` on the VNet interface and `deny-lan`) |
| N07 | a-t1 | gateway `10.64.1.1` tcp 22 and 8006 | tcp | filtered (guest-to-host drop) |
| N08 | a-t1, b-t1 | ICS on a port that is **not** the callback port: 8088 and 22 | tcp | filtered; only the callback port is open |
| N09 | a-t1 | one other LAN address that is *not* in any ipset (the LAN gateway `192.168.22.1` tcp 22 only) | tcp | filtered (`deny-lan`); no other LAN host is probed |
| N10 | a-t1 | public internet, one connection to a literal documented address (the repo host is allowed; use `1.1.1.1:443`) | tcp | filtered (no default egress) |
| N11 | edge host | a-t1 on a non-published port (3306 and 9200) | tcp | filtered (only the published list is open) |
| N12 | a non-edge LAN host that the owner designates (not the ICS) | a-t1:443 | tcp | filtered (inbound only from `ou_edge`) |
| N13 | a-t1 sends a frame with a forged source of B's subnet: `ip addr add <B ip>/24 dev eth0` in a throw-away test VM, then connect to a-t2 and to the repo | tcp | blocked or no reply (VM-level ip/mac spoof protection or no route; documents behaviour: **if it passes, record as a finding**: enable `ipfilter`/MAC filter on the NIC) |
| N14 | a-t1 | a-t1's own cloud metadata/other tenant services on `169.254.169.254` | tcp 80 | no response (no metadata service on the VNet) |

## C. Control-plane and Proxmox-side checks (ICS, no guests involved)
| ID | Check | Expected |
|---|---|---|
| C01 | `POST /deployments/plan` for customer A with `bridge=ouc02` | `network_not_assigned` naming customer B; plan not executable |
| C02 | plan for a customer with no assignment | `network_unassigned` |
| C03 | endpoint `allowed_networks` without `ouc01`, plan for A | `network_out_of_scope`; and a forced provider call (test harness) is refused by `EndpointScope.network_ok` before any API call |
| C04 | ICS token attaches a NIC to `vmbr0` after the localnetwork grant was removed (provider harness on a throw-away VM) | Proxmox 403 `SDN.Use` (and the ICS refuses first) |
| C05 | `pveum user token permissions officeunbound@pam ics --path /sdn` | no `SDN.Allocate`, no write privilege |
| C06 | VNet firewall options and rule order (`ORDER OK`), `nft list ruleset` contains the drop rules | as documented |
| C07 | Plan `network.flows` equals the PVE rules actually applied (diff by script: flows -> expected `ou_*` rules) | identical |
| C08 | Destroy customer A deployment | its VNet, firewall rules and B's connectivity unchanged (rerun P01, P09 for B) |

## D. Execution order and evidence
1. Create A and B throw-away VMs (4 VMs) via the ICS in their own VNets. 2. Run section A (all PASS) before any NEG, so a failing negative is meaningful. 3. Run B and C. 4. Repeat A/B on the real stacks (one `id` and one `files` VM per customer is enough for the cross-customer set; all VMs for the inbound set). 5. Re-run after every ICS upgrade and after any firewall change; keep the output with the release evidence (`blueprints/lab/tests/t20_tenant_isolation.py` section `network` should be pointed at the same guests: expected "0 cross probes open without any host rule"). 6. Destroy the test VMs and confirm pool membership is back to the baseline.
Status values per ADR-0000: results stay "Planned" until a run's evidence is quoted here.
