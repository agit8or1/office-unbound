#!/bin/bash
# Provision the lab desktop-client machine (ou-desk2: clone of ou-base-noble, Ubuntu 24.04) for the client-compatibility tests.
# Run INSIDE the machine as root. Idempotent. Lab only.
#   env: LAB_CA_FILES="/path/ou-lab-ca.crt /path/gw1-ca.crt" (public CA certs, installed into the system store)
#        TB_VERSION (default 153.7.0esr, the Mozilla ESR line)
# Thunderbird: Mozilla's official linux-x86_64 tarball, verified with the SHA256SUMS file that is verified with Mozilla's
# release-signing key (primary fingerprint pinned below; a mismatch aborts). Licence MPL-2.0. Evolution + evolution-ews come from
# Ubuntu (GPL / LGPL). Nothing is fetched at test time.
set -euo pipefail
TB_VERSION="${TB_VERSION:-153.7.0esr}"
MOZ_FPR="14F26682D0916CDD81E37B6D61B7B526D98F0353"   # Mozilla Software Releases <release@mozilla.com>
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq --no-install-recommends xvfb xdotool xauth gnupg libnss3-tools bzip2 xz-utils imagemagick openssl curl ca-certificates \
  libgtk-3-0t64 libdbus-glib-1-2 libasound2t64 libx11-xcb1 libxtst6 libxt6t64 libpci3 fonts-dejavu-core dbus-x11 \
  python3-requests python3-gi gir1.2-edataserver-1.2 gir1.2-ecal-2.0 gir1.2-ebook-1.2 gir1.2-camel-1.2 gir1.2-glib-2.0 \
  evolution evolution-ews gnome-keyring libsecret-tools

for f in ${LAB_CA_FILES:-}; do cp "$f" "/usr/local/share/ca-certificates/$(basename "$f" .crt).crt"; done
update-ca-certificates >/dev/null

# --- Thunderbird, checksum + signature verified
if [ ! -x /opt/thunderbird/thunderbird ]; then
  W=$(mktemp -d); cd "$W"
  B="https://ftp.mozilla.org/pub/thunderbird/releases/${TB_VERSION}"
  curl -sSfO "$B/KEY"; curl -sSfO "$B/SHA256SUMS"; curl -sSfO "$B/SHA256SUMS.asc"; curl -sSfO "$B/linux-x86_64/en-US/thunderbird-${TB_VERSION}.tar.xz"
  export GNUPGHOME="$W/gnupg"; mkdir -m700 "$GNUPGHOME"
  gpg --batch --import KEY 2>/dev/null
  gpg --batch --with-colons --fingerprint | grep -q "^fpr:::::::::${MOZ_FPR}:" || { echo "Mozilla key fingerprint mismatch"; exit 1; }
  gpg --batch --verify SHA256SUMS.asc SHA256SUMS 2>&1 | grep -q "Good signature from \"Mozilla Software Releases" || { echo "SHA256SUMS signature invalid"; exit 1; }
  want=$(grep " linux-x86_64/en-US/thunderbird-${TB_VERSION}.tar.xz\$" SHA256SUMS | cut -d' ' -f1)
  got=$(sha256sum "thunderbird-${TB_VERSION}.tar.xz" | cut -d' ' -f1)
  [ -n "$want" ] && [ "$want" = "$got" ] || { echo "tarball checksum mismatch"; exit 1; }
  tar -C /opt -xJf "thunderbird-${TB_VERSION}.tar.xz"
  echo "Thunderbird ${TB_VERSION}: sha256 ${got} verified against the signed SHA256SUMS"
fi

# --- unix users: tester (Thunderbird), evo1/evo2 (one Evolution Data Server session each), evom (debug)
for u in tester evo1 evo2; do id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"; done
for u in evo1 evo2; do d=/run/user/$(id -u "$u"); mkdir -p "$d"; chown "$u" "$d"; chmod 700 "$d"; done
mkdir -p /root/cc /home/tester/tb; chmod 755 /root /root/cc
cat > /home/tester/tb/user.js <<'EOF'
user_pref("marionette.enabled", true);
user_pref("marionette.port", 2828);
user_pref("marionette.prefs.recommended", false);
user_pref("signon.rememberSignons", true);
user_pref("mail.shell.checkDefaultClient", false);
user_pref("mail.provider.enabled", false);
user_pref("app.update.auto", false);
user_pref("app.update.enabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("mailnews.start_page.enabled", false);
user_pref("mail.rights.version", 1);
EOF
chown -R tester:tester /home/tester
echo "ou-desk2 provisioned"
