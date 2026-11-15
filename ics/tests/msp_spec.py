"""OpenAPI 3.1 conformance helper: loads docs/api/msp-v1.yaml and validates a response against the schema of its operation.
A small JSON-Schema subset validator (type incl. nullable type lists, required, properties, items, enum, allOf/oneOf/anyOf, $ref, pattern,
min/max, additionalProperties:false) - enough for the schemas in the spec; no third-party dependency."""
import os
import re

import yaml

SPEC_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "docs", "api", "msp-v1.yaml")
_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


def load():
    with open(SPEC_PATH) as f:
        return yaml.safe_load(f)


SPEC = load()


def _resolve(ref: str):
    node = SPEC
    for part in ref.lstrip("#/").split("/"):
        node = node[part]
    return node


def validate(value, schema: dict, path: str = "$") -> list[str]:
    errs: list[str] = []
    if "$ref" in schema:
        return validate(value, _resolve(schema["$ref"]), path)
    for sub in schema.get("allOf", []):
        errs += validate(value, sub, path)
    if "oneOf" in schema and sum(not validate(value, s, path) for s in schema["oneOf"]) != 1:
        errs.append(f"{path}: not exactly one oneOf matches")
    if "anyOf" in schema and not any(not validate(value, s, path) for s in schema["anyOf"]):
        errs.append(f"{path}: no anyOf matches")
    t = schema.get("type")
    if t is not None:
        ts = t if isinstance(t, list) else [t]

        def ok(x, tt):
            if tt == "integer":
                return isinstance(x, int) and not isinstance(x, bool)
            if tt == "number":
                return isinstance(x, (int, float)) and not isinstance(x, bool)
            return isinstance(x, _TYPES[tt]) and not (tt != "boolean" and isinstance(x, bool) and tt in ("string", "object", "array"))
        if not any(ok(value, tt) for tt in ts):
            return errs + [f"{path}: expected {ts}, got {type(value).__name__} ({str(value)[:40]!r})"]
    if "enum" in schema and value not in schema["enum"]:
        errs.append(f"{path}: {value!r} not in enum {schema['enum']}")
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errs.append(f"{path}: does not match {schema['pattern']}")
        if "minLength" in schema and len(value) < schema["minLength"]:
            errs.append(f"{path}: shorter than {schema['minLength']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errs.append(f"{path}: below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            errs.append(f"{path}: above maximum")
    if isinstance(value, dict):
        for r in schema.get("required", []):
            if r not in value:
                errs.append(f"{path}: missing required {r!r}")
        props = schema.get("properties", {})
        for k, v in value.items():
            if k in props:
                errs += validate(v, props[k], f"{path}.{k}")
            elif schema.get("additionalProperties") is False:
                errs.append(f"{path}: unexpected property {k!r}")
            elif isinstance(schema.get("additionalProperties"), dict):
                errs += validate(v, schema["additionalProperties"], f"{path}.{k}")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errs.append(f"{path}: fewer than {schema['minItems']} items")
        if "items" in schema:
            for i, v in enumerate(value):
                errs += validate(v, schema["items"], f"{path}[{i}]")
    return errs


def match_operation(method: str, path: str):
    """path is relative to /api/msp/v1 (no query). Returns (template, operation) or None."""
    for tmpl, item in SPEC["paths"].items():
        rx = "^" + re.sub(r"\{[^}]+\}", "[^/]+", tmpl) + "$"
        if re.match(rx, path) and method.lower() in item:
            return tmpl, item[method.lower()]
    return None


def response_schema(op: dict, status: int):
    resps = op["responses"]
    r = resps.get(str(status)) or resps.get(f"{status // 100}XX") or resps.get("default")
    if r is None:
        return None, False
    if "$ref" in r:
        r = _resolve(r["$ref"])
    c = r.get("content", {}).get("application/json")
    return (c["schema"] if c else None), True


def check_response(method: str, path: str, status: int, body) -> list[str]:
    m = match_operation(method, path.split("?")[0])
    if m is None:
        return [f"no operation for {method} {path}"]
    schema, declared = response_schema(m[1], status)
    if not declared:
        return [f"status {status} not declared for {method} {m[0]}"]
    return validate(body, schema, "$") if schema else []
