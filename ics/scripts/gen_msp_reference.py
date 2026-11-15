"""Generate docs/api/msp-v1-reference.md from docs/api/msp-v1.yaml:  python scripts/gen_msp_reference.py [--check]"""
import os
import sys

import yaml

ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "docs", "api")


def ref_name(r):
    return r.rsplit("/", 1)[-1]


def type_of(s: dict) -> str:
    if "$ref" in s:
        return f"[{ref_name(s['$ref'])}](#{ref_name(s['$ref']).lower()})"
    if "allOf" in s:
        return " + ".join(type_of(x) for x in s["allOf"])
    t = s.get("type", "any")
    t = " or ".join(t) if isinstance(t, list) else t
    if t == "array" and "items" in s:
        t = f"array of {type_of(s['items'])}"
    if "enum" in s:
        t += " (" + ", ".join(str(x) for x in s["enum"] if x is not None) + ")"
    return t


def render(spec: dict) -> str:
    out = [f"# {spec['info']['title']} {spec['info']['version']} — reference", "",
           "_Generated from `docs/api/msp-v1.yaml` by `ics/scripts/gen_msp_reference.py`; do not edit._", "",
           spec["info"]["description"].strip(), "", "## Operations", ""]
    out += ["| Method | Path | Permission | operationId | Summary |", "|---|---|---|---|---|"]
    for path, item in spec["paths"].items():
        for m, op in item.items():
            if m in ("get", "post", "patch", "put", "delete"):
                out.append(f"| {m.upper()} | `/api/msp/v1{path}` | {op['x-permission']} | {op['operationId']} | {op.get('summary', '')} |")
    out += ["", "## Operation details", ""]
    for path, item in spec["paths"].items():
        shared = item.get("parameters", [])
        for m, op in item.items():
            if m not in ("get", "post", "patch", "put", "delete"):
                continue
            out += [f"### {m.upper()} `/api/msp/v1{path}`", "", f"**{op['operationId']}** — permission `{op['x-permission']}`"
                    + (" — requires `Idempotency-Key`" if m != "get" else ""), ""]
            if op.get("summary"):
                out += [op["summary"], ""]
            params = [spec["components"]["parameters"][ref_name(p["$ref"])] if "$ref" in p else p for p in shared + op.get("parameters", [])]
            if params:
                out += ["| Parameter | In | Type | Required |", "|---|---|---|---|"]
                out += [f"| `{p['name']}` | {p['in']} | {type_of(p.get('schema', {}))} | {'yes' if p.get('required') else 'no'} |" for p in params]
                out.append("")
            rb = op.get("requestBody")
            if rb:
                out += [f"Request body: {type_of(rb['content']['application/json']['schema'])}", ""]
            out += ["| Status | Response |", "|---|---|"]
            for code, r in op["responses"].items():
                if "$ref" in r:
                    r = spec["components"]["responses"][ref_name(r["$ref"])]
                c = r.get("content", {}).get("application/json")
                out.append(f"| {code} | {r.get('description', '')}{' — ' + type_of(c['schema']) if c else ''} |")
            out.append("")
    out += ["## Schemas", ""]
    for name, s in spec["components"]["schemas"].items():
        out += [f"### {name}", ""]
        props = dict(s.get("properties", {}))
        for sub in s.get("allOf", []):
            if "properties" in sub:
                props.update(sub["properties"])
        req = set(s.get("required", [])) | {r for sub in s.get("allOf", []) for r in sub.get("required", [])}
        if not props:
            out += [f"`{type_of(s)}`", ""]
            continue
        out += ["| Field | Type | Required | Description |", "|---|---|---|---|"]
        out += [f"| `{k}` | {type_of(v)} | {'yes' if k in req else 'no'} | {v.get('description', '')} |" for k, v in props.items()]
        out.append("")
    return "\n".join(out) + "\n"


def main() -> int:
    with open(os.path.join(ROOT, "msp-v1.yaml")) as f:
        text = render(yaml.safe_load(f))
    target = os.path.join(ROOT, "msp-v1-reference.md")
    if "--check" in sys.argv:
        return 0 if os.path.exists(target) and open(target).read() == text else 1
    with open(target, "w") as f:
        f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
