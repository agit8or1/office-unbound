import json, sys
sys.path.insert(0, "/root/agent-code")
from ou_agent import firstboot
conf = firstboot.validate_config(json.load(open("/root/conf3.json  # lab: the metadata rendered by lab_artifact_client.py render")))
firstboot.apply_trust(firstboot.Guest("/"), conf)
print("trust re-applied from the bootstrap metadata:", [r["suite"] for r in conf["ou_repos"]], conf["image_repos"])
