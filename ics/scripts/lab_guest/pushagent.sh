#!/bin/sh
# lab: upgrade the agent in ou-guest1 from the worktree exactly the way an installer re-run does (enrollment is kept)
set -eu
S=/tmp/claude-1000/-home-administrator/a1d917f8-7438-424e-a57a-793b46deb95e/scratchpad
cd /home/administrator/office-unbound/.claude/worktrees/agent-a3d8c4dce9755d94e/ics
PYTHONPATH=. /home/administrator/office-unbound/ics/.venv/bin/python -c "
from ics.guest import cloudinit as ci
open('$S/bundle.tgz','wb').write(ci.build_agent_bundle('agent'))"
sudo cp $S/bundle.tgz /var/lib/machines/ou-guest1/root/bundle.tgz
sudo machinectl shell ou-guest1 /bin/sh -c 'rm -rf /root/b && mkdir /root/b && tar -xzf /root/bundle.tgz -C /root/b --no-same-owner && cp /etc/ou-agent/agent.src.json /root/b/agent-guest.json && cd /root/b && sh install-agent.sh 192.168.186.168 ou-guest1 agent-guest.json > /root/reinstall.log 2>&1; echo rc=$?; systemctl is-active ou-agent; ls /var/lib/ou-agent' 2>&1 | tail -4
