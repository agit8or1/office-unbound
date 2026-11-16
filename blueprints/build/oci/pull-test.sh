#!/bin/bash
# Pull test under a sigstoreSigned policy (run as root inside the lab machine ou-img2): every listed <repo>@<digest> must pull; an unsigned digest, a converted
# (re-encoded, therefore different digest) copy of a signed image and a signature made with another channel's key must be refused.
# usage: pull-test.sh <registry host:port> <pubkey.pem of the channel> <other-channel-pubkey.pem> <repo@digest>...
set -uo pipefail
REG=$1; KEY=$2; OTHER=$3; shift 3
S=/tmp/ou-pull-test; rm -rf "$S"; mkdir -p "$S/reg.d" "$S/storage"
cat > "$S/reg.d/lab.yaml" <<E
docker:
  $REG:
    use-sigstore-attachments: true
E
mkpol() { cat > "$S/$1" <<E
{"default":[{"type":"reject"}],"transports":{"docker":{"$REG":[{"type":"sigstoreSigned","keyPath":"$2","signedIdentity":{"type":"matchRepository"}}]}}}
E
}
mkpol policy.json "$KEY"; mkpol policy-other.json "$OTHER"
P() { podman --storage-driver vfs --root "$S/storage" --runroot "$S/run" --registries-conf "$S/registries.conf" --signature-policy "$1" "${@:2}"; }
printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$REG" > "$S/registries.conf"
export CONTAINERS_REGISTRIES_CONF_DIR="$S/reg.d"
SK() { skopeo --registries.d "$S/reg.d" --policy "$1" "${@:2}"; }
fail=0
for ref in "$@"; do
  if SK "$S/policy.json" copy --src-tls-verify=false "docker://$REG/$ref" "dir:$S/out" >"$S/o.txt" 2>&1; then echo "PASS pull (signed, policy of the right channel): $ref"; rm -rf "$S/out"; else echo "FAIL $ref"; tail -2 "$S/o.txt"; fail=1; fi
done
first=$1
if SK "$S/policy-other.json" copy --src-tls-verify=false "docker://$REG/$first" "dir:$S/out" >"$S/o.txt" 2>&1; then echo "FAIL: accepted with the OTHER channel's key"; fail=1; else echo "PASS refused with another channel's key: $(tail -1 "$S/o.txt" | cut -c1-160)"; fi
repo=${first%@*}
cat > "$S/policy-allow.json" <<E
{"default":[{"type":"insecureAcceptAnything"}]}
E
# swap: another image (second argument, or the lab office image) pushed WITHOUT signatures under this repository: an unsigned digest in a signed repo
foreign=${2:-$first}
SK "$S/policy-allow.json" copy --remove-signatures --src-tls-verify=false --dest-tls-verify=false "docker://$REG/$foreign" "docker://$REG/$repo:swapped" >"$S/o.txt" 2>&1 || { cat "$S/o.txt"; fail=1; }
if SK "$S/policy.json" copy --src-tls-verify=false "docker://$REG/$repo:swapped" "dir:$S/out2" >"$S/o.txt" 2>&1; then echo "FAIL: unsigned (swapped) image accepted"; fail=1; else echo "PASS unsigned/tampered reference refused: $(tail -1 "$S/o.txt" | cut -c1-200)"; fi
# the same through podman pull with the system policy (what the deployment executor runs)
mkdir -p /etc/containers/registries.d; cp -a /etc/containers/policy.json "$S/policy.orig" 2>/dev/null || true
cp "$S/policy.json" /etc/containers/policy.json; cp "$S/reg.d/lab.yaml" /etc/containers/registries.d/ou-lab.yaml
PP() { podman --storage-driver vfs --root "$S/storage" --runroot "$S/run" --registries-conf "$S/registries.conf" "$@"; }
if PP pull --tls-verify=false "$REG/$repo:swapped" >"$S/o.txt" 2>&1; then echo "FAIL: podman pull accepted the unsigned image"; fail=1; else echo "PASS podman pull refused the unsigned image: $(tail -1 "$S/o.txt" | cut -c1-160)"; fi
for ref in "$@"; do
  if PP pull --tls-verify=false "$REG/$ref" >"$S/o.txt" 2>&1; then echo "PASS podman pull of the signed digest succeeded: $ref"; else echo "FAIL podman pull signed $ref: $(tail -2 "$S/o.txt")"; fail=1; fi
done
[ -f "$S/policy.orig" ] && cp "$S/policy.orig" /etc/containers/policy.json; rm -f /etc/containers/registries.d/ou-lab.yaml
rm -rf "$S/storage"
exit $fail
