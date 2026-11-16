#!/bin/bash
# Lab proof of the artifact distribution service (ADR-0015, docs/status/artifact-dist-results.md).
# Machines (systemd-nspawn, zone oulab): SRV=ou-dist1 runs ou-artifacts-setup.sh and holds the published apt tree + registry;
# CLI=ou-dist-client1 was configured by ou_agent.firstboot.apply_trust from the bootstrap metadata rendered by lab_artifact_client.py (positive
# apt/podman tests were run by hand before this script; this script is the NEGATIVE matrix). Run as a user with sudo (machinectl/systemd-run).
set -u
SRV=${SRV:-ou-dist1}; CLI=${CLI:-ou-dist-client1}; HOSTPORT=${HOSTPORT:-192.168.186.120:8444}
SOFT=sha256:efc5d8b4ad04b70e25d66b3ef9219c5009f4ee33d328005d6ed3accaa8b33941
MEET=sha256:69b20d09d661d29ad5482e9603dfe628d5ca176925513c5d312ba04513e1e283
SYN=sha256:542de3d410dc142cf45c69e42c13cbd970a497803dc7edb78c3e2b2ee5160a9d
inm() { local m=$1; shift; sudo -n systemd-run -M "$m" --pipe --wait -q --collect /bin/bash -c "$*" 2>&1; }
pull() { inm $CLI "runuser -u ou-svc -- env HOME=/var/lib/ou-svc XDG_RUNTIME_DIR=/run/user/1000 /usr/bin/podman rmi -a -f >/dev/null 2>&1; echo local-images-before-pull: \$(runuser -u ou-svc -- env HOME=/var/lib/ou-svc XDG_RUNTIME_DIR=/run/user/1000 /usr/bin/podman images -q | wc -l); /root/pull.sh $HOSTPORT/ou/$1@$2 ${3:-} | tail -3"; }
hdr() { echo; echo "=== $* ==="; }
CA=/etc/ou-agent/artifact-ca.crt
RDIR=/var/lib/office-unbound/artifacts/registry/docker/registry/v2

hdr "N-1 (re)apply the guest trust configuration (what the golden image first boot writes) so every run starts from the same state"
inm $CLI "python3 -I /root/apply.py"

hdr "N0 publish more images (signed by dev key)"
inm $SRV "ou-artifact-publish oci --from http://192.168.186.235:5000 --repo ou/meet-token-service --ref 0.1.0-ou1 --channel dev; echo rc=\$?"

hdr "P1 positive: pull by digest under sigstoreSigned, identity exactRepository (expect rc=0)"
pull ou-softphone $SOFT

hdr "N1 signed image whose repository is not in this VM's plan -> refused by the registry-wide reject scope"
inm $SRV "ou-artifact-publish oci --from http://192.168.186.235:5000 --repo ou/synapse --ref 1.165.0 --channel dev | cut -c1-120"
pull synapse $SYN

hdr "N2 UNSIGNED image (signature attachment removed from the registry store) -> refused"
HEX=${MEET#sha256:}
inm $SRV "cd $RDIR/repositories/ou/meet-token-service/_manifests/tags && mv sha256-$HEX.sig /root/sig.saved && ls"
pull meet-token-service $MEET
inm $SRV "cd $RDIR/repositories/ou/meet-token-service/_manifests/tags && mv /root/sig.saved sha256-$HEX.sig && ls | head -3"
echo "-- restored; same pull again (expect rc=0):"; pull meet-token-service $MEET

hdr "N3 WRONG CHANNEL KEY: image signed by the dev key, guest pinned the stable image key -> refused"
inm $CLI "cp /etc/ou-agent/image-policy.json /tmp/policy-stable.json; cp /root/ou-image-stable.pub.pem /tmp/stable.pub; sed -i 's#/etc/ou-agent/image-signing.pub#/tmp/stable.pub#' /tmp/policy-stable.json; chmod 644 /tmp/policy-stable.json /tmp/stable.pub"
pull ou-softphone $SOFT /tmp/policy-stable.json

hdr "N4 TAMPERED MANIFEST on the server -> refused (digest mismatch)"
M=$RDIR/blobs/sha256/${SOFT:7:2}/${SOFT#sha256:}/data
inm $SRV "cp -p $M /root/manifest.orig && printf ' ' >> $M && sha256sum $M | cut -c1-20"
pull ou-softphone $SOFT
inm $SRV "cat /root/manifest.orig > $M && sha256sum $M | cut -c1-20"

hdr "N5 TAMPERED LAYER on the server -> refused"
L=$(inm $SRV "python3 -c \"import json;m=json.load(open('$M'));print(m['layers'][0]['digest'][7:])\"")
LP=$RDIR/blobs/sha256/${L:0:2}/$L/data
inm $SRV "cp -p $LP /root/layer.orig && printf 'X' | dd of=$LP bs=1 seek=100 conv=notrunc 2>/dev/null; sha256sum $LP | cut -c1-20"
pull ou-softphone $SOFT
inm $SRV "cat /root/layer.orig > $LP && sha256sum $LP | cut -c1-20; echo restored; rm -f /root/layer.orig"
echo "-- after restore (expect rc=0):"; pull ou-softphone $SOFT

hdr "N6 PUSH / WRITE from the client is refused (GET and HEAD only)"
inm $CLI "for m in PUT POST PATCH DELETE; do printf '%s /v2/ou/ou-softphone/blobs/uploads/ -> ' \$m; curl -s -o /dev/null -w '%{http_code}\n' --cacert $CA -X \$m https://$HOSTPORT/v2/ou/ou-softphone/blobs/uploads/; done; for m in PUT DELETE; do printf '%s /apt/dists/dev/InRelease -> ' \$m; curl -s -o /dev/null -w '%{http_code}\n' --cacert $CA -X \$m --data x https://$HOSTPORT/apt/dists/dev/InRelease; done; printf 'PUT manifest -> '; curl -s -o /dev/null -w '%{http_code}\n' --cacert $CA -X PUT --data '{}' https://$HOSTPORT/v2/ou/ou-softphone/manifests/evil"
echo "-- podman push from the guest:"
inm $CLI "runuser -u ou-svc -- env HOME=/var/lib/ou-svc XDG_RUNTIME_DIR=/run/user/1000 /usr/bin/podman push --remove-signatures --tls-verify=true --cert-dir /etc/containers/certs.d/$HOSTPORT $HOSTPORT/ou/ou-softphone@$SOFT docker://$HOSTPORT/ou/evil:1 2>&1 | tail -2"
echo "-- the push socket is not reachable from the network (no listener but 127.0.0.1:5001 and nginx):"
inm $SRV "ss -ltnH | awk '{print \$4}' | sort; ls -l /run/ou-artifacts 2>&1 | head -2; systemctl is-active ou-registry-push"
echo "-- registry reader itself is read-only (direct write to loopback reader):"
inm $SRV "curl -s -o /dev/null -w 'POST uploads on the reader -> %{http_code}\n' -X POST http://127.0.0.1:5001/v2/ou/evil/blobs/uploads/"

hdr "N7 NO LISTINGS of internal content"
inm $CLI "for u in /apt/ /apt/dists/ /apt/pool/ /apt/pool/dev/ /apt/dists/dev/ /v2/_catalog /v2/ou/ou-softphone/tags/list /v2/ou/ou-softphone/referrers/$SOFT /apt/.. /apt/dists/dev/../../../etc/passwd /apt/dists/dev/InRelease /v2/ /healthz /nothing; do printf '%-48s -> ' \$u; curl -s --path-as-is -o /dev/null -w '%{http_code}\n' --cacert $CA https://$HOSTPORT\$u; done"

# apt-install attempt from a CLEAN state (no cached .deb, no cached lists), so a cached good copy can never mask a refusal
try_install() {
  inm $CLI "dpkg -r ou-libhx >/dev/null 2>&1; apt-get clean; rm -rf /var/lib/ou-pkg/lists/*; echo before: \$(dpkg -l ou-libhx 2>&1 | tail -1 | cut -c1-50); python3 -I /root/client_apt.py ou-libhx 4.28-ou1 | tr -d '\n ' | cut -c1-300; echo; echo after: \$(dpkg -l ou-libhx 2>&1 | tail -1 | cut -c1-50); echo apt-says:; rm -rf /var/lib/ou-pkg/lists/*; apt-get -o Dir::Etc::sourcelist=/etc/ou-agent/apt/sources.list -o Dir::Etc::sourceparts=/nonexistent -o Dir::State::lists=/var/lib/ou-pkg/lists -c /etc/ou-agent/apt/apt-extra.conf update 2>&1 | grep -E '^(E|W|Err):' | cut -c1-230 | head -4"
}
CUR=/var/lib/office-unbound/artifacts/apt/current
hdr "N8 apt: TAMPERED PACKAGE, TAMPERED INDEX, TAMPERED InRelease are refused (published tree modified on the server)"
echo "-- control: untouched tree installs (expect ok):"; try_install
inm $SRV "cd $CUR && cp -p pool/dev/libhx/ou-libhx_4.28-ou1_amd64.deb /root/deb.orig && cp -p dists/dev/InRelease /root/inrelease.orig && cp -p dists/dev/main/binary-amd64/Packages.gz /root/packages.gz.orig"
echo "-- 8a package bytes changed after signing:"
inm $SRV "printf 'X' | dd of=$CUR/pool/dev/libhx/ou-libhx_4.28-ou1_amd64.deb bs=1 seek=200 conv=notrunc 2>/dev/null"
try_install
inm $SRV "cat /root/deb.orig > $CUR/pool/dev/libhx/ou-libhx_4.28-ou1_amd64.deb"
echo "-- 8b Packages index (the .gz apt actually downloads) changed after signing:"
inm $SRV "zcat /root/packages.gz.orig | sed 's/^Depends: libc6.*/Depends: evil/' | gzip -n > $CUR/dists/dev/main/binary-amd64/Packages.gz"
try_install
inm $SRV "cat /root/packages.gz.orig > $CUR/dists/dev/main/binary-amd64/Packages.gz"
echo "-- 8c InRelease text changed (signature no longer matches):"
inm $SRV "sed -i 's/^Label: .*/Label: evil/' $CUR/dists/dev/InRelease"
try_install
inm $SRV "cat /root/inrelease.orig > $CUR/dists/dev/InRelease"
echo "-- restored; install again (expect ok):"; try_install

hdr "N9 apt WRONG CHANNEL KEY: a VM that installs from stable only, whose stable keyring holds the DEV key -> refused"
inm $CLI "cp /etc/ou-agent/apt/keyrings/ou-stable.asc /root/ou-stable.asc.orig; cp /etc/ou-agent/apt/keyrings/ou-dev.asc /etc/ou-agent/apt/keyrings/ou-stable.asc; cp /etc/ou-agent/apt/sources.list /root/sources.orig; grep -v ' dev main' /root/sources.orig > /etc/ou-agent/apt/sources.list"
try_install
inm $CLI "cp /root/sources.orig /etc/ou-agent/apt/sources.list"
echo "-- a key that is NOT in pinned-fingerprints -> repo_key_mismatch before any download:"
inm $CLI "cp /root/ou-stable.asc.orig /etc/ou-agent/apt/keyrings/ou-stable.asc; cp /etc/ou-agent/apt/pinned-fingerprints /root/pins.orig; grep -v 3082B558 /root/pins.orig > /etc/ou-agent/apt/pinned-fingerprints; python3 -I /root/client_apt.py ou-libhx 4.28-ou1 | tr -d '\n' | cut -c1-300; echo; cp /root/pins.orig /etc/ou-agent/apt/pinned-fingerprints"
echo "-- restored; install (expect ok):"; try_install

hdr "N10 publisher refuses bad input (nothing published)"
inm $SRV "mkdir -p /root/bad/dists /root/bad/pool && cp -a /root/build-repo/dists/dev /root/bad/dists/dev && cp -a /root/build-repo/pool/dev /root/bad/pool/dev && sed -i 's/^Label: .*/Label: evil/' /root/bad/dists/dev/InRelease; ou-artifact-publish apt --src /root/bad --channels dev; echo rc=\$?; ou-artifact-publish status"
inm $SRV "rm -rf /root/bad; rm -rf /root/wrong && mkdir -p /root/wrong/dists && cp -a /root/build-repo/dists/stable /root/wrong/dists/dev && mkdir -p /root/wrong/pool && cp -a /root/build-repo/pool/stable /root/wrong/pool/dev; ou-artifact-publish apt --src /root/wrong --channels dev; echo rc=\$?; rm -rf /root/wrong"
inm $SRV "ou-artifact-publish oci --from http://192.168.186.235:5000 --repo ou/synapse --ref 1.165.0 --channel stable; echo rc=\$?"

hdr "N11 rate limit: 400 requests in a burst from one client address"
inm $CLI "python3 - <<'PY'
import ssl, urllib.request, urllib.error, concurrent.futures as cf, collections
ctx = ssl.create_default_context(cafile='$CA')
def one(_):
    try:
        return urllib.request.urlopen('https://$HOSTPORT/v2/', context=ctx, timeout=20).status
    except urllib.error.HTTPError as e:
        return e.code
with cf.ThreadPoolExecutor(16) as ex:
    print(dict(collections.Counter(ex.map(one, range(400)))))
PY"

hdr "LOGS (dedicated access log, last entries by status)"
inm $SRV "for s in 405 403 429 404; do grep -m2 \" \$s \" /var/log/nginx/ou-artifacts.access.log; done; wc -l /var/log/nginx/ou-artifacts.access.log"
