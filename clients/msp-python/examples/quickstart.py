"""Create a customer, preview a deployment and plan a user, then wait for the human approval.

    OU_ICS_URL=https://ics.example OU_MSP_CLIENT=mspc_... OU_MSP_SECRET=mspk_... python examples/quickstart.py
Every call is a signed request; every mutation carries an Idempotency-Key (generated per call, reused on retries). Mutations only ever create
PLANS: nothing changes until the plan's approvers have approved it and the ICS worker has run the job.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ou_msp import MspClient  # noqa: E402

api = MspClient(os.environ["OU_ICS_URL"], os.environ["OU_MSP_CLIENT"], os.environ["OU_MSP_SECRET"])
print("me:", api.me())

# 1. customer (plan; two human approvers)
plan = api.create_customer(name="Example GmbH", external_ref="crm-4711", contact_email="it@example.test")
print("customer plan:", plan["plan_id"], plan["status"], "approvals required:", plan["approvals_required"])
final = api.wait_for_plan(plan["plan_id"], timeout=3600, interval=10)  # production integrations should use webhooks instead of polling
customer_id = final["execution"]["result"]["customer_id"]

# 2. deployment preview (dry run), then the plan that echoes its hash
spec = {"deployment_id": "example-prod", "profile": "small", "users": 40, "domain": "example.test", "endpoint": "lab", "pool": "example"}
preview = api.preview_deployment(customer_id, spec)
print("preview executable:", preview["executable"], "VMs:", preview["consumption"]["vms"], "plan_hash:", preview["plan_hash"][:12])
if preview["executable"]:
    dep = api.create_deployment(customer_id, spec, preview["plan_hash"])
    print("deployment plan:", dep["plan_id"], dep["status"], dep["risk"])

# 3. a user (idm lifecycle; needs an identity stack linked to the customer)
user = api.create_user(customer_id, uid="alice", display_name="Alice Example", mail="alice@example.test", groups=["staff"])
print("user plan:", user["plan_id"], user["status"], user["risk"])
print("usage:", api.usage(customer_id)["users"])
