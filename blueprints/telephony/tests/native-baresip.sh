#!/usr/bin/env bash
# Runs INSIDE ou-pbx1 as root. Native SIP client (baresip) over TLS 1.2 + SDES-SRTP (mandatory) registers as carol.native and calls
# the echo test extension 600. stdin: "<username> <password>"; args: <extension-to-dial> <call-seconds>. Prints baresip's log + result lines.
# The credential goes to a tmpfs file (/run/baresip-test, 0700) that is deleted at the end; it is never echoed.
set -u
read -r USER_ PASS_   # credential arrives on stdin (not argv, so it is not visible in a process list)
DIAL="$1"; SECS="${2:-8}"; PBXH="${PBX_HOST:-pbx.ou-lab.internal}"; PBXIP="${PBX_IP:-192.168.186.247}"
D=/run/baresip-test; rm -rf $D; install -d -m 0700 $D

# 8 s of 440 Hz tone as the audio source (what we "speak"), 8 kHz mono 16 bit
python3 - <<'PY'
import wave, math, struct
w = wave.open("/run/baresip-test/src.wav", "wb"); w.setnchannels(1); w.setsampwidth(2); w.setframerate(8000)
w.writeframes(b"".join(struct.pack("<h", int(12000 * math.sin(2 * math.pi * 440 * i / 8000))) for i in range(8000 * 30)))
w.close()
PY
cat > $D/config <<EOF
sip_cafile /etc/ou-lab/tls/ca.crt
sip_verify_server yes
audio_player aufile,$D/rx.wav
audio_source aufile,$D/src.wav
audio_alert aufile,$D/alert.wav
call_local_timeout 10
module_path /usr/lib/baresip/modules
module stdio.so
module menu.so
module g711.so
module aufile.so
module srtp.so
module account.so
EOF
printf '<sip:%s@%s;transport=tls>;auth_pass=%s;mediaenc=srtp-mand;regint=60;outbound="sip:%s;transport=tls"\n' "$USER_" "$PBXH" "$PASS_" "$PBXIP" > $D/accounts
chmod 600 $D/accounts
(
  sleep 4; echo "/dial sip:$DIAL@$PBXH"
  sleep "$SECS"; echo "/hangup"
  sleep 2; echo "/quit"
) | timeout 60 baresip -f $D 2>&1 | grep --line-buffered -v -i -E "auth_pass|audio=|^\s*$|^\/|\x1b\[0" | tee $D/log | sed 's/^/BARESIP: /' &
BP=$!
sleep $((4 + SECS / 2 + 1))
echo "PBX-SIDE-DURING-CALL:"; asterisk -rx "core show channels concise"; asterisk -rx "pjsip show channelstats"; sleep 1; asterisk -rx "pjsip show channelstats"
asterisk -rx "pjsip show contacts" | grep -E "Contact:|Objects"
wait $BP 2>/dev/null; sleep 1
echo "RX-WAV-BYTES: $(stat -c %s $D/rx.wav 2>/dev/null || echo 0)"
rm -rf $D
