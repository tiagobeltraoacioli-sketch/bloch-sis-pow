#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) Bloch community contributors
#
# Bloch SDK code generator.
#
# The spec drives the clients. This script reads docs/openapi.yaml — the single
# source of truth for the Bloch JSON-RPC 2.0 surface — and deterministically
# emits typed clients into sdk/python/ and sdk/go/. Re-run it whenever the spec
# changes; never hand-edit the generated models/client files.
#
#   python3 sdk/codegen/generate.py
#
# It is dependency-light: stdlib only, plus PyYAML to parse the spec.

from __future__ import annotations

import os
import subprocess
import sys
from collections import OrderedDict

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "This generator needs PyYAML to parse docs/openapi.yaml.\n"
        "Install it with:  python3 -m pip install pyyaml\n"
    )
    raise SystemExit(1)

# ── Paths ───────────────────────────────────────────────────────────────────
HERE = os.path.dirname(os.path.abspath(__file__))
SDK_ROOT = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(SDK_ROOT)
SPEC_PATH = os.path.join(REPO_ROOT, "docs", "openapi.yaml")
PY_OUT = os.path.join(SDK_ROOT, "python")
GO_OUT = os.path.join(SDK_ROOT, "go")

SPEC_REL = "docs/openapi.yaml"

PY_BANNER = f"# @generated from {SPEC_REL} — do not edit by hand.\n"
GO_BANNER = f"// @generated from {SPEC_REL} — do not edit by hand.\n"
PY_SPDX = "# SPDX-License-Identifier: MIT OR Apache-2.0\n"
GO_SPDX = "// SPDX-License-Identifier: MIT OR Apache-2.0\n"

# JSON-RPC envelope schemas are handled by the hand-written transport, not
# emitted as domain models.
SKIP_SCHEMAS = {
    "JsonRpcRequest",
    "JsonRpcResponse",
    "JsonRpcErrorResponse",
    "JsonRpcError",
}

# Scalar schema aliases: (python_type, go_type).
#
# `Satoshis` is NOT a plain scalar. The Genesis-4 supply cap is 10^19 sat
# (crates/bloch-pos-committee/src/tokenomics_v4.rs) — 108% of int64's positive
# range and ~1000x JavaScript's 2^53 exact-integer limit — so the wire form is
# a decimal string and each language binds its own codec:
#   Go     -> the `Satoshis` type in satoshis.go (uint64 + string JSON)
#   Python -> `Satoshis` = the wire union, with parse_sats() in units.py
# Both are emitted from static assets, not from this table, so they are listed
# in ALIAS_EMIT_SKIP below.
SCALAR_ALIASES = OrderedDict(
    [
        ("Hex32", ("str", "string")),
        ("Hex20", ("str", "string")),
        ("Address", ("str", "string")),
        ("Satoshis", ("Satoshis", "Satoshis")),
    ]
)

# Aliases whose declaration is hand-written (in a static asset or emitted with
# a bespoke line) rather than generated as `type X = Y`.
GO_ALIAS_EMIT_SKIP = {"Satoshis"}

# Curated word splits so generated method names read well in each language.
# Key = JSON-RPC method name (sent on the wire, unchanged).
WORD_SPLITS = {
    "getnetworkinfo": ["get", "network", "info"],
    "getblockcount": ["get", "block", "count"],
    "getmempoolinfo": ["get", "mempool", "info"],
    "getdaginfo": ["get", "dag", "info"],
    "getpeerinfo": ["get", "peer", "info"],
    "getpeers": ["get", "peers"],
    "getblockhash": ["get", "block", "hash"],
    "getblock": ["get", "block"],
    "getblockbyheight": ["get", "block", "by", "height"],
    "getrecentblocks": ["get", "recent", "blocks"],
    "gettxsbyblock": ["get", "txs", "by", "block"],
    "gettransaction": ["get", "transaction"],
    "gettxstatus": ["get", "tx", "status"],
    "decoderawtransaction": ["decode", "raw", "transaction"],
    "getrawmempool": ["get", "raw", "mempool"],
    "getmempoolstats": ["get", "mempool", "stats"],
    "getbalance": ["get", "balance"],
    "getutxos": ["get", "utxos"],
    "getaddressinfo": ["get", "address", "info"],
    "getaddressbalance_at_height": ["get", "address", "balance", "at", "height"],
    "getaddresscount": ["get", "address", "count"],
    "listtransactions": ["list", "transactions"],
    "validateaddress": ["validate", "address"],
    "validateaddressverbose": ["validate", "address", "verbose"],
    "estimatefee": ["estimate", "fee"],
    "estimatefeeadvanced": ["estimate", "fee", "advanced"],
    "sendrawtransaction": ["send", "raw", "transaction"],
    "getchainstats": ["get", "chain", "stats"],
    "gethashrate": ["get", "hashrate"],
    "getsupplydistribution": ["get", "supply", "distribution"],
    "getdifficultyhistory": ["get", "difficulty", "history"],
    "getblocktimepercentiles": ["get", "block", "time", "percentiles"],
    "getpools": ["get", "pools"],
    "getattestation": ["get", "attestation"],
    "getblocktemplate": ["get", "block", "template"],
    "submitblock": ["submit", "block"],
}

WRITE_METHODS = {"sendrawtransaction", "submitblock"}


def snake_name(method: str) -> str:
    return "_".join(WORD_SPLITS[method])


def pascal_name(method: str) -> str:
    return "".join(w.capitalize() for w in WORD_SPLITS[method])


def cap(s: str) -> str:
    return s[:1].upper() + s[1:]


# ── Spec loading ────────────────────────────────────────────────────────────
def load_spec():
    with open(SPEC_PATH, "r", encoding="utf-8") as fh:
        spec = yaml.safe_load(fh)
    schemas = spec["components"]["schemas"]
    methods = spec["x-json-rpc-methods"]
    info = spec.get("info", {})
    return spec, schemas, methods, info


def ref_name(schema):
    if isinstance(schema, dict) and "$ref" in schema:
        return schema["$ref"].split("/")[-1]
    return None


def is_object_schema(schema):
    return isinstance(schema, dict) and (
        "properties" in schema or schema.get("type") == "object"
    )


def is_scalar_schema(schema):
    return (
        isinstance(schema, dict)
        and schema.get("type") in ("string", "integer", "number", "boolean")
        and "properties" not in schema
    )


def split_oneof(schema):
    """Return (non_null_variants, has_null) for a oneOf schema."""
    variants = schema.get("oneOf", [])
    non_null = [v for v in variants if not (isinstance(v, dict) and v.get("type") == "null")]
    has_null = any(isinstance(v, dict) and v.get("type") == "null" for v in variants)
    return non_null, has_null


# ── Synthetic (inline nested object) model registry ─────────────────────────
# Some schemas nest an anonymous object (e.g. Pools.pools). We hoist those into
# named models so both languages get a concrete type.
SYNTHETICS: "OrderedDict[str, dict]" = OrderedDict()


def register_synthetics(name, schema):
    if not isinstance(schema, dict):
        return
    props = schema.get("properties", {})
    for pname, pschema in props.items():
        if isinstance(pschema, dict) and is_object_schema(pschema) and "$ref" not in pschema:
            syn_name = name + cap(pname)
            SYNTHETICS[syn_name] = pschema
            register_synthetics(syn_name, pschema)
        elif isinstance(pschema, dict) and pschema.get("type") == "array":
            items = pschema.get("items", {})
            if isinstance(items, dict) and is_object_schema(items) and "$ref" not in items:
                syn_name = name + cap(pname) + "Item"
                SYNTHETICS[syn_name] = items
                register_synthetics(syn_name, items)


def synthetic_name_for(parent, pname):
    return parent + cap(pname)


def synthetic_item_name_for(parent, pname):
    return parent + cap(pname) + "Item"


# ════════════════════════════════════════════════════════════════════════════
#  PYTHON EMISSION
# ════════════════════════════════════════════════════════════════════════════
def py_type(schema, parent=None, pname=None):
    if schema is None or schema == {}:
        return "Any"
    if not isinstance(schema, dict):
        return "Any"
    if "$ref" in schema:
        return ref_name(schema)
    if "oneOf" in schema:
        non_null, has_null = split_oneof(schema)
        parts = []
        for v in non_null:
            t = py_type(v, parent, pname)
            if t not in parts:
                parts.append(t)
        if len(parts) == 1:
            inner = parts[0]
        else:
            inner = "Union[" + ", ".join(parts) + "]"
        return f"Optional[{inner}]" if has_null else inner
    t = schema.get("type")
    if t == "array":
        items = schema.get("items", {})
        if isinstance(items, dict) and is_object_schema(items) and "$ref" not in items and parent:
            return f"List[{synthetic_item_name_for(parent, pname)}]"
        return f"List[{py_type(items, parent, pname)}]"
    if t == "object":
        if "properties" in schema and parent:
            return synthetic_name_for(parent, pname)
        return "Dict[str, Any]"
    if t == "string":
        return "str"
    if t == "integer":
        return "int"
    if t == "number":
        return "float"
    if t == "boolean":
        return "bool"
    if "const" in schema:
        cv = schema["const"]
        return "bool" if isinstance(cv, bool) else ("int" if isinstance(cv, int) else "str")
    return "Any"


def emit_python_model(name, schema):
    """Emit one TypedDict (object or merged oneOf) or nothing for scalars."""
    lines = []
    # Merged oneOf-of-objects -> one total=False TypedDict of all fields.
    if isinstance(schema, dict) and "oneOf" in schema and "properties" not in schema:
        non_null, _ = split_oneof(schema)
        merged = OrderedDict()
        desc = schema.get("description")
        for variant in non_null:
            if isinstance(variant, dict) and "$ref" in variant:
                # e.g. SubmitBlockResult includes ResultError by ref.
                merged.setdefault("error", {"type": "string"})
                continue
            for pn, ps in (variant.get("properties", {}) or {}).items():
                merged.setdefault(pn, ps)
        lines.append(f"class {name}(TypedDict, total=False):")
        if desc:
            lines.append(f'    """{one_line(desc)} (merged union of variant shapes)."""')
        if not merged:
            lines.append("    pass")
        for pn, ps in merged.items():
            lines.append(f"    {pn}: {py_type(ps, name, pn)}")
        lines.append("")
        return "\n".join(lines)

    # Plain object -> TypedDict.
    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    desc = schema.get("description") if isinstance(schema, dict) else None
    lines.append(f"class {name}(TypedDict, total=False):")
    if desc:
        lines.append(f'    """{one_line(desc)}"""')
    if not props:
        lines.append("    pass")
    for pn, ps in props.items():
        lines.append(f"    {pn}: {py_type(ps, name, pn)}")
    lines.append("")
    return "\n".join(lines)


def one_line(text):
    return " ".join(str(text).split())


def py_default_literal(param):
    if "default" in param:
        d = param["default"]
        if isinstance(d, bool):
            return "True" if d else "False"
        return repr(d)
    return "None"


def build_python_models(schemas):
    out = []
    out.append(PY_SPDX)
    out.append("# Copyright (c) Bloch community contributors\n")
    out.append(PY_BANNER)
    out.append("#\n")
    out.append("# Typed models for the Bloch JSON-RPC surface (TypedDicts + scalar aliases).\n")
    out.append("# The integer satoshi field is the on-chain truth; the float `*_bloch`\n")
    out.append("# fields are display-only. See units.py.\n\n")
    out.append("from __future__ import annotations\n\n")
    out.append("from typing import Any, Dict, List, Optional, Union\n")
    out.append("from typing import TypedDict\n\n\n")

    # Scalar aliases first.
    out.append("# ── Scalar aliases ─────────────────────────────────────────────────────────\n")
    for alias, (pyt, _got) in SCALAR_ALIASES.items():
        if alias == "Satoshis":
            out.append(
                "# A satoshi amount as it appears ON THE WIRE: a decimal string in V4,\n"
                "# a bare int from legacy Genesis-3 nodes. Never do arithmetic on the raw\n"
                "# field — run it through units.parse_sats() first, which accepts both\n"
                "# forms and returns an exact Python int.\n"
                "Satoshis = Union[str, int]\n"
            )
            continue
        out.append(f"{alias} = {pyt}\n")
    out.append("Height = int\n")
    out.append("\n\n")

    out.append("# ── Models ─────────────────────────────────────────────────────────────────\n\n")
    for name, schema in schemas.items():
        if name in SKIP_SCHEMAS or name in SCALAR_ALIASES:
            continue
        out.append(emit_python_model(name, schema))
        out.append("\n")
    # Synthetic nested models.
    for name, schema in SYNTHETICS.items():
        out.append(emit_python_model(name, schema))
        out.append("\n")
    return "".join(out)


def python_method_signature(method, spec_m):
    params = spec_m.get("params", []) or []
    required = [p for p in params if p.get("required")]
    optional = [p for p in params if not p.get("required")]
    args = ["self"]
    for p in required:
        args.append(f"{py_param_name(p['name'])}: {py_param_type(p)}")
    for p in optional:
        args.append(f"{py_param_name(p['name'])}: {py_param_type(p, optional=True)} = {py_default_literal(p)}")
    ret = py_return_type(spec_m.get("result", {}))
    return required, optional, f"({', '.join(args)}) -> {ret}"


def py_param_name(name):
    return name


def py_param_type(param, optional=False):
    t = param.get("type")
    base = {
        "integer": "int",
        "string": "str",
        "boolean": "bool",
        "number": "float",
    }.get(t, "Any")
    if optional and "default" not in param:
        return f"Optional[{base}]"
    return base


def py_return_type(result):
    return f'"{py_type(result)}"'


def build_python_client(methods):
    out = []
    out.append(PY_SPDX)
    out.append("# Copyright (c) Bloch community contributors\n")
    out.append(PY_BANNER)
    out.append("#\n")
    out.append("# Typed JSON-RPC 2.0 client for Bloch over the single `POST /` endpoint\n")
    out.append("# (default port 16210). Normalizes BOTH failure shapes:\n")
    out.append("#   1. the standard top-level `error` object (transport/auth: -32001/-32002)\n")
    out.append("#   2. the non-standard string `result.error` (HTTP 200, most method errors)\n\n")
    out.append("from __future__ import annotations\n\n")
    out.append("import json\n")
    out.append("import socket\n")
    out.append("import urllib.error\n")
    out.append("import urllib.request\n")
    out.append("from typing import Any, Dict, List, Optional, Union\n\n")
    out.append("from .errors import BlochRpcError, BlochTransportError\n")
    out.append("from .models import *  # noqa: F401,F403 (typed model names for annotations)\n")
    out.append("from .signer import Signer  # noqa: F401 (re-export the write-path seam)\n\n")
    out.append('DEFAULT_RPC_URL = "http://127.0.0.1:16210"\n')
    out.append("DEFAULT_RPC_PORT = 16210\n\n\n")

    # Helper for trimming trailing default optional params.
    out.append(
        "def _trim_optionals(pairs: List[Any]) -> List[Any]:\n"
        '    """pairs: list of (value, default). Drop trailing entries whose value\n'
        "    equals its default; keep interior ones (they become JSON null / value).\"\"\"\n"
        "    items = list(pairs)\n"
        "    while items and items[-1][0] == items[-1][1]:\n"
        "        items.pop()\n"
        "    return [v for v, _ in items]\n\n\n"
    )

    out.append("class BlochClient:\n")
    out.append('    """A typed client for the Bloch JSON-RPC surface.\n\n')
    out.append("    Every method maps to one node RPC. Reads are public; the only write is\n")
    out.append("    :meth:`send_raw_transaction` (already-signed raw tx hex). Failures raise\n")
    out.append("    :class:`BlochRpcError` (both error shapes normalized) or\n")
    out.append('    :class:`BlochTransportError` (network / malformed response)."""\n\n')
    out.append(
        "    def __init__(\n"
        "        self,\n"
        "        url: str = DEFAULT_RPC_URL,\n"
        "        *,\n"
        "        api_key: Optional[str] = None,\n"
        "        bearer: bool = False,\n"
        "        timeout: float = 30.0,\n"
        "        headers: Optional[Dict[str, str]] = None,\n"
        "    ) -> None:\n"
        "        self.url = url\n"
        "        self.api_key = api_key\n"
        "        self.bearer = bearer\n"
        "        self.timeout = timeout\n"
        "        self.static_headers = dict(headers or {})\n"
        "        self._id = 0\n\n"
    )

    # The transport / _call.
    out.append(
        "    def call(self, method: str, params: Optional[List[Any]] = None) -> Any:\n"
        '        """Low-level JSON-RPC call. Prefer the typed wrappers below."""\n'
        "        self._id += 1\n"
        '        payload = {"jsonrpc": "2.0", "method": method, "params": params or [], "id": self._id}\n'
        "        body = json.dumps(payload).encode(\"utf-8\")\n"
        "        headers = {\"Content-Type\": \"application/json\"}\n"
        "        headers.update(self.static_headers)\n"
        "        if self.api_key is not None:\n"
        "            if self.bearer:\n"
        '                headers["Authorization"] = f"Bearer {self.api_key}"\n'
        "            else:\n"
        '                headers["X-API-Key"] = self.api_key\n'
        "        req = urllib.request.Request(self.url, data=body, headers=headers, method=\"POST\")\n"
        "        status = 0\n"
        "        raw = b\"\"\n"
        "        try:\n"
        "            with urllib.request.urlopen(req, timeout=self.timeout) as resp:\n"
        "                status = getattr(resp, \"status\", resp.getcode())\n"
        "                raw = resp.read()\n"
        "        except urllib.error.HTTPError as exc:\n"
        "            # Transport/auth failures (401/429) arrive here with a JSON body.\n"
        "            status = exc.code\n"
        "            try:\n"
        "                raw = exc.read()\n"
        "            except Exception:\n"
        "                raw = b\"\"\n"
        "        except (urllib.error.URLError, socket.timeout, OSError) as exc:\n"
        "            raise BlochTransportError(\n"
        "                f\"RPC transport error calling {method}: {exc}\", method=method\n"
        "            ) from exc\n"
        "        try:\n"
        "            parsed = json.loads(raw.decode(\"utf-8\")) if raw else None\n"
        "        except (ValueError, UnicodeDecodeError) as exc:\n"
        "            raise BlochTransportError(\n"
        "                f\"RPC {method}: response was not valid JSON (HTTP {status})\",\n"
        "                method=method,\n"
        "                http_status=status,\n"
        "            ) from exc\n"
        "        envelope = parsed if isinstance(parsed, dict) else {}\n"
        "        # Shape 1: standard top-level error object (transport/auth).\n"
        "        err = envelope.get(\"error\")\n"
        "        if isinstance(err, dict):\n"
        "            raise BlochRpcError(\n"
        "                str(err.get(\"message\", \"JSON-RPC error\")),\n"
        "                method=method,\n"
        "                source=\"jsonrpc-error\",\n"
        "                code=err.get(\"code\") if isinstance(err.get(\"code\"), int) else None,\n"
        "                http_status=status,\n"
        "                data=err.get(\"data\"),\n"
        "            )\n"
        "        if status and status >= 400:\n"
        "            raise BlochTransportError(\n"
        "                f\"RPC {method}: HTTP {status}\", method=method, http_status=status\n"
        "            )\n"
        "        result = envelope.get(\"result\")\n"
        "        # Shape 2: non-standard string result.error (HTTP 200).\n"
        "        if isinstance(result, dict) and isinstance(result.get(\"error\"), str):\n"
        "            raise BlochRpcError(\n"
        "                result[\"error\"], method=method, source=\"result-error\", data=result\n"
        "            )\n"
        "        return result\n\n"
    )

    # Typed wrappers.
    for method, spec_m in methods.items():
        required, optional, sig = python_method_signature(method, spec_m)
        py_name = snake_name(method)
        out.append(f"    def {py_name}{sig}:\n")
        doc = build_doc(method, spec_m)
        if doc:
            out.append(f'        """{doc}"""\n')
        # Build params.
        if not required and not optional:
            out.append(f'        return self.call("{method}")\n\n')
            continue
        req_names = [py_param_name(p["name"]) for p in required]
        if optional:
            opt_pairs = ", ".join(
                f'({py_param_name(p["name"])}, {py_default_literal(p)})' for p in optional
            )
            if req_names:
                out.append(f"        params: List[Any] = [{', '.join(req_names)}]\n")
            else:
                out.append("        params: List[Any] = []\n")
            out.append(f"        params.extend(_trim_optionals([{opt_pairs}]))\n")
            out.append(f'        return self.call("{method}", params)\n\n')
        else:
            out.append(f'        return self.call("{method}", [{", ".join(req_names)}])\n\n')
    return "".join(out)


def build_doc(method, spec_m):
    cat = spec_m.get("category", "")
    write = " (WRITE — needs X-API-Key on a non-local node when auth is on)" if method in WRITE_METHODS else ""
    return f"JSON-RPC `{method}` [{cat}]{write}."


# ════════════════════════════════════════════════════════════════════════════
#  GO EMISSION
# ════════════════════════════════════════════════════════════════════════════
def go_scalar(t):
    return {
        "string": "string",
        "integer": "int64",
        "number": "float64",
        "boolean": "bool",
    }.get(t, "interface{}")


def go_field_type(schema, parent=None, pname=None):
    if not isinstance(schema, dict) or schema == {}:
        return "interface{}"
    if "$ref" in schema:
        name = ref_name(schema)
        if name in SCALAR_ALIASES:
            return SCALAR_ALIASES[name][1]
        return "*" + name
    if "oneOf" in schema:
        non_null, has_null = split_oneof(schema)
        if len(non_null) == 1:
            inner = go_field_type(non_null[0], parent, pname)
            if has_null and not inner.startswith("*") and not inner.startswith("[]"):
                return "*" + inner
            return inner
        return "interface{}"
    t = schema.get("type")
    if t == "array":
        items = schema.get("items", {})
        return "[]" + go_element_type(items, parent, pname)
    if t == "object":
        if "properties" in schema and parent:
            return "*" + synthetic_name_for(parent, pname)
        return "map[string]interface{}"
    if t in ("string", "integer", "number", "boolean"):
        return go_scalar(t)
    if "const" in schema:
        cv = schema["const"]
        if isinstance(cv, bool):
            return "bool"
        if isinstance(cv, int):
            return "int64"
        return "string"
    return "interface{}"


def go_element_type(items, parent=None, pname=None):
    if not isinstance(items, dict) or items == {}:
        return "interface{}"
    if "$ref" in items:
        name = ref_name(items)
        if name in SCALAR_ALIASES:
            return SCALAR_ALIASES[name][1]
        return name
    if is_object_schema(items) and parent:
        return synthetic_item_name_for(parent, pname)
    t = items.get("type")
    if t in ("string", "integer", "number", "boolean"):
        return go_scalar(t)
    return "interface{}"


def go_return_type(result):
    if not isinstance(result, dict) or result == {}:
        return "interface{}"
    if "$ref" in result:
        name = ref_name(result)
        if name in SCALAR_ALIASES:
            return SCALAR_ALIASES[name][1]
        return "*" + name
    if "oneOf" in result:
        non_null, _ = split_oneof(result)
        if len(non_null) == 1:
            return go_return_type(non_null[0])
        return "interface{}"
    t = result.get("type")
    if t == "array":
        return "[]" + go_element_type(result.get("items", {}))
    if t == "object":
        return "map[string]interface{}"
    if t in ("string", "integer", "number", "boolean"):
        return go_scalar(t)
    return "interface{}"


def go_exported(name):
    # JSON property -> exported Go field name.
    return "".join(cap(part) for part in name.replace("-", "_").split("_"))


def emit_go_model(name, schema):
    lines = []
    # Merged oneOf-of-objects.
    if isinstance(schema, dict) and "oneOf" in schema and "properties" not in schema:
        non_null, _ = split_oneof(schema)
        merged = OrderedDict()
        for variant in non_null:
            if isinstance(variant, dict) and "$ref" in variant:
                merged.setdefault("error", {"type": "string"})
                continue
            for pn, ps in (variant.get("properties", {}) or {}).items():
                merged.setdefault(pn, ps)
        desc = schema.get("description")
        if desc:
            lines.append(f"// {name} — {one_line(desc)}")
            lines.append(f"// (merged union of variant shapes; fields are optional).")
        lines.append(f"type {name} struct {{")
        for pn, ps in merged.items():
            ft = go_field_type(ps, name, pn)
            if not ft.startswith("*") and not ft.startswith("[]"):
                ft = "*" + ft  # union fields are optional
            lines.append(f"\t{go_exported(pn)} {ft} `json:\"{pn},omitempty\"`")
        lines.append("}")
        lines.append("")
        return "\n".join(lines)

    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    desc = schema.get("description") if isinstance(schema, dict) else None
    if desc:
        lines.append(f"// {name} — {one_line(desc)}")
    lines.append(f"type {name} struct {{")
    for pn, ps in props.items():
        ft = go_field_type(ps, name, pn)
        lines.append(f"\t{go_exported(pn)} {ft} `json:\"{pn},omitempty\"`")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def build_go_models(schemas):
    out = []
    out.append(GO_SPDX)
    out.append("// Copyright (c) Bloch community contributors\n")
    out.append(GO_BANNER)
    out.append("//\n")
    out.append("// Typed models for the Bloch JSON-RPC surface.\n")
    out.append("// The integer satoshi field is the on-chain truth; float `*_bloch` fields\n")
    out.append("// are display-only. See units.go.\n\n")
    out.append("package blochclient\n\n")
    out.append("// ── Scalar aliases ──────────────────────────────────────────────────────────\n\n")
    for alias, (_pyt, got) in SCALAR_ALIASES.items():
        if alias in GO_ALIAS_EMIT_SKIP:
            out.append(f"// {alias} is declared in {alias.lower()}.go (uint64 in memory, decimal\n")
            out.append("// string on the wire). See docs/specs/BLOCH-SATOSHI-ENCODING.md.\n")
            continue
        out.append(f"type {alias} = {got}\n")
    out.append("type Height = int64\n\n")
    out.append("// ── Models ──────────────────────────────────────────────────────────────────\n\n")
    for name, schema in schemas.items():
        if name in SKIP_SCHEMAS or name in SCALAR_ALIASES:
            continue
        out.append(emit_go_model(name, schema))
        out.append("\n")
    for name, schema in SYNTHETICS.items():
        out.append(emit_go_model(name, schema))
        out.append("\n")
    return "".join(out)


def go_param_name(name):
    parts = name.replace("-", "_").split("_")
    return parts[0] + "".join(cap(p) for p in parts[1:])


def go_param_type(param):
    t = param.get("type")
    base = go_scalar(t) if t else "interface{}"
    # Optional params with no static default become pointers (nil = default/tip).
    if not param.get("required") and "default" not in param:
        return "*" + base
    return base


def go_zero_default(param):
    """Return a Go literal equal to this optional param's declared default."""
    if "default" in param:
        d = param["default"]
        if isinstance(d, bool):
            return "true" if d else "false"
        if isinstance(d, str):
            return '"' + d + '"'
        return str(d)
    return "nil"


def build_go_client(methods):
    out = []
    out.append(GO_SPDX)
    out.append("// Copyright (c) Bloch community contributors\n")
    out.append(GO_BANNER)
    out.append("//\n")
    out.append("// Typed JSON-RPC 2.0 client for Bloch over the single POST / endpoint\n")
    out.append("// (default port 16210). Normalizes BOTH failure shapes:\n")
    out.append("//   1. standard top-level `error` object (transport/auth: -32001/-32002)\n")
    out.append("//   2. non-standard string `result.error` (HTTP 200, most method errors)\n\n")
    out.append("package blochclient\n\n")
    out.append("import (\n")
    out.append('\t"bytes"\n')
    out.append('\t"encoding/json"\n')
    out.append('\t"fmt"\n')
    out.append('\t"io"\n')
    out.append('\t"net/http"\n')
    out.append('\t"sync/atomic"\n')
    out.append('\t"time"\n')
    out.append(")\n\n")
    out.append('const DefaultRPCURL = "http://127.0.0.1:16210"\n')
    out.append("const DefaultRPCPort = 16210\n\n")

    out.append(
        "// Client is a typed client for the Bloch JSON-RPC surface. Reads are public;\n"
        "// the only write is SendRawTransaction (already-signed raw tx hex).\n"
        "type Client struct {\n"
        "\tURL        string\n"
        "\tAPIKey     string\n"
        "\tBearer     bool\n"
        "\tHTTPClient *http.Client\n"
        "\tHeaders    map[string]string\n"
        "\tid         int64\n"
        "}\n\n"
    )
    out.append(
        "// New returns a Client pointed at url (empty = DefaultRPCURL) with a 30s timeout.\n"
        "func New(url string) *Client {\n"
        "\tif url == \"\" {\n"
        "\t\turl = DefaultRPCURL\n"
        "\t}\n"
        "\treturn &Client{URL: url, HTTPClient: &http.Client{Timeout: 30 * time.Second}}\n"
        "}\n\n"
    )

    # Envelope + transport.
    out.append(
        "type rpcRequest struct {\n"
        "\tJSONRPC string        `json:\"jsonrpc\"`\n"
        "\tMethod  string        `json:\"method\"`\n"
        "\tParams  []interface{} `json:\"params\"`\n"
        "\tID      int64         `json:\"id\"`\n"
        "}\n\n"
        "type rpcErrorObject struct {\n"
        "\tCode    int             `json:\"code\"`\n"
        "\tMessage string          `json:\"message\"`\n"
        "\tData    json.RawMessage `json:\"data\"`\n"
        "}\n\n"
        "type rpcEnvelope struct {\n"
        "\tJSONRPC string           `json:\"jsonrpc\"`\n"
        "\tID      interface{}      `json:\"id\"`\n"
        "\tResult  json.RawMessage  `json:\"result\"`\n"
        "\tError   *rpcErrorObject  `json:\"error\"`\n"
        "}\n\n"
    )
    out.append(
        "// Call is the low-level JSON-RPC call. Prefer the typed wrappers. out may be\n"
        "// nil (result discarded) or a pointer to unmarshal the result into.\n"
        "func (c *Client) Call(method string, params []interface{}, out interface{}) error {\n"
        "\tif params == nil {\n"
        "\t\tparams = []interface{}{}\n"
        "\t}\n"
        "\tid := atomic.AddInt64(&c.id, 1)\n"
        "\tbody, err := json.Marshal(rpcRequest{JSONRPC: \"2.0\", Method: method, Params: params, ID: id})\n"
        "\tif err != nil {\n"
        "\t\treturn &TransportError{Method: method, Message: fmt.Sprintf(\"marshal request: %v\", err)}\n"
        "\t}\n"
        "\treq, err := http.NewRequest(\"POST\", c.URL, bytes.NewReader(body))\n"
        "\tif err != nil {\n"
        "\t\treturn &TransportError{Method: method, Message: fmt.Sprintf(\"build request: %v\", err)}\n"
        "\t}\n"
        "\treq.Header.Set(\"Content-Type\", \"application/json\")\n"
        "\tfor k, v := range c.Headers {\n"
        "\t\treq.Header.Set(k, v)\n"
        "\t}\n"
        "\tif c.APIKey != \"\" {\n"
        "\t\tif c.Bearer {\n"
        "\t\t\treq.Header.Set(\"Authorization\", \"Bearer \"+c.APIKey)\n"
        "\t\t} else {\n"
        "\t\t\treq.Header.Set(\"X-API-Key\", c.APIKey)\n"
        "\t\t}\n"
        "\t}\n"
        "\thc := c.HTTPClient\n"
        "\tif hc == nil {\n"
        "\t\thc = http.DefaultClient\n"
        "\t}\n"
        "\tresp, err := hc.Do(req)\n"
        "\tif err != nil {\n"
        "\t\treturn &TransportError{Method: method, Message: fmt.Sprintf(\"transport error: %v\", err)}\n"
        "\t}\n"
        "\tdefer resp.Body.Close()\n"
        "\traw, err := io.ReadAll(resp.Body)\n"
        "\tif err != nil {\n"
        "\t\treturn &TransportError{Method: method, HTTPStatus: resp.StatusCode, Message: fmt.Sprintf(\"read body: %v\", err)}\n"
        "\t}\n"
        "\tvar env rpcEnvelope\n"
        "\tif len(raw) > 0 {\n"
        "\t\tif err := json.Unmarshal(raw, &env); err != nil {\n"
        "\t\t\treturn &TransportError{Method: method, HTTPStatus: resp.StatusCode, Message: fmt.Sprintf(\"response was not valid JSON: %v\", err)}\n"
        "\t\t}\n"
        "\t}\n"
        "\t// Shape 1: standard top-level error object (transport/auth).\n"
        "\tif env.Error != nil {\n"
        "\t\treturn &RPCError{Method: method, Source: \"jsonrpc-error\", Code: env.Error.Code, HTTPStatus: resp.StatusCode, Message: env.Error.Message}\n"
        "\t}\n"
        "\tif resp.StatusCode >= 400 {\n"
        "\t\treturn &TransportError{Method: method, HTTPStatus: resp.StatusCode, Message: fmt.Sprintf(\"HTTP %d\", resp.StatusCode)}\n"
        "\t}\n"
        "\t// Shape 2: non-standard string result.error (HTTP 200).\n"
        "\tif len(env.Result) > 0 {\n"
        "\t\tvar probe map[string]json.RawMessage\n"
        "\t\tif json.Unmarshal(env.Result, &probe) == nil {\n"
        "\t\t\tif rawErr, ok := probe[\"error\"]; ok {\n"
        "\t\t\t\tvar msg string\n"
        "\t\t\t\tif json.Unmarshal(rawErr, &msg) == nil {\n"
        "\t\t\t\t\treturn &RPCError{Method: method, Source: \"result-error\", Message: msg}\n"
        "\t\t\t\t}\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t}\n"
        "\tif out != nil && len(env.Result) > 0 {\n"
        "\t\tif err := json.Unmarshal(env.Result, out); err != nil {\n"
        "\t\t\treturn &TransportError{Method: method, HTTPStatus: resp.StatusCode, Message: fmt.Sprintf(\"decode result: %v\", err)}\n"
        "\t\t}\n"
        "\t}\n"
        "\treturn nil\n"
        "}\n\n"
    )

    # Typed wrappers.
    for method, spec_m in methods.items():
        params = spec_m.get("params", []) or []
        required = [p for p in params if p.get("required")]
        optional = [p for p in params if not p.get("required")]
        go_name = pascal_name(method)
        ret = go_return_type(spec_m.get("result", {}))
        # Signature args.
        arglist = []
        for p in required:
            arglist.append(f"{go_param_name(p['name'])} {go_param_type(p)}")
        for p in optional:
            arglist.append(f"{go_param_name(p['name'])} {go_param_type(p)}")
        doc = f"// {go_name} calls JSON-RPC `{method}`"
        if method in WRITE_METHODS:
            doc += " (WRITE — needs X-API-Key on a non-local node when auth is on)"
        doc += "."
        out.append(doc + "\n")
        out.append(f"func (c *Client) {go_name}({', '.join(arglist)}) ({ret}, error) {{\n")

        # Build params slice.
        if not required and not optional:
            out.append("\tparams := []interface{}{}\n")
        else:
            req_names = [go_param_name(p["name"]) for p in required]
            out.append(f"\tparams := []interface{{}}{{{', '.join(req_names)}}}\n")
            if optional:
                # Append optionals, trimming trailing entries equal to default.
                out.append("\topt := []struct {\n\t\tv   interface{}\n\t\tdef bool\n\t}{\n")
                for p in optional:
                    pn = go_param_name(p["name"])
                    default_lit = go_zero_default(p)
                    if default_lit == "nil":
                        cond = f"{pn} == nil"
                    else:
                        cond = f"{pn} == {default_lit}"
                    out.append(f"\t\t{{{pn}, {cond}}},\n")
                out.append("\t}\n")
                out.append("\tlastKeep := -1\n")
                out.append("\tfor i := range opt {\n\t\tif !opt[i].def {\n\t\t\tlastKeep = i\n\t\t}\n\t}\n")
                out.append("\tfor i := 0; i <= lastKeep; i++ {\n\t\tparams = append(params, opt[i].v)\n\t}\n")

        # Return handling.
        emit_go_return(out, ret, method)
        out.append("}\n\n")
    return "".join(out)


def emit_go_return(out, ret, method):
    if ret.startswith("*"):
        base = ret[1:]
        out.append(f"\tout := new({base})\n")
        out.append(f'\terr := c.Call("{method}", params, out)\n')
        out.append("\tif err != nil {\n\t\treturn nil, err\n\t}\n")
        out.append("\treturn out, nil\n")
    elif ret.startswith("[]"):
        out.append(f"\tvar out {ret}\n")
        out.append(f'\terr := c.Call("{method}", params, &out)\n')
        out.append("\tif err != nil {\n\t\treturn nil, err\n\t}\n")
        out.append("\treturn out, nil\n")
    elif ret == "interface{}":
        out.append("\tvar out interface{}\n")
        out.append(f'\terr := c.Call("{method}", params, &out)\n')
        out.append("\treturn out, err\n")
    else:
        out.append(f"\tvar out {ret}\n")
        out.append(f'\terr := c.Call("{method}", params, &out)\n')
        out.append("\treturn out, err\n")


# ════════════════════════════════════════════════════════════════════════════
#  STATIC FILES (scaffold, written deterministically)
# ════════════════════════════════════════════════════════════════════════════
from static_assets import (  # noqa: E402
    LICENSE_MIT,
    LICENSE_APACHE,
    PY_ERRORS,
    PY_UNITS,
    PY_SIGNER,
    PY_INIT,
    PY_PYPROJECT,
    PY_README,
    PY_GITIGNORE,
    GO_ERRORS,
    GO_UNITS,
    GO_SATOSHIS,
    GO_SATOSHIS_TEST,
    GO_SIGNER,
    GO_DOC,
    GO_MOD,
    GO_README,
    GO_GITIGNORE,
    CODEGEN_README,
)


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def gofmt(paths):
    """Best-effort `gofmt -w` over the emitted Go files.

    The emitter writes single-space struct fields; gofmt column-aligns them.
    Running it here keeps regeneration byte-identical to what is committed, so
    a re-run never shows up as spurious diff. Skipped silently when the Go
    toolchain is absent — the output is valid Go either way.
    """
    go_files = [p for p in paths if p.endswith(".go")]
    if not go_files:
        return False
    try:
        subprocess.run(["gofmt", "-w", *go_files], check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError):
        return False
    return True


def main():
    spec, schemas, methods, info = load_spec()

    # Register synthetic nested models (across primary schemas).
    for name, schema in schemas.items():
        if name in SKIP_SCHEMAS or name in SCALAR_ALIASES:
            continue
        register_synthetics(name, schema)

    version = info.get("version", "0.0.0")

    written = []

    # ── Python package ──
    written.append(write(os.path.join(PY_OUT, "blochclient", "models.py"), build_python_models(schemas)))
    written.append(write(os.path.join(PY_OUT, "blochclient", "client.py"), build_python_client(methods)))
    written.append(write(os.path.join(PY_OUT, "blochclient", "errors.py"), PY_ERRORS))
    written.append(write(os.path.join(PY_OUT, "blochclient", "units.py"), PY_UNITS))
    written.append(write(os.path.join(PY_OUT, "blochclient", "signer.py"), PY_SIGNER))
    written.append(write(os.path.join(PY_OUT, "blochclient", "__init__.py"), PY_INIT.replace("@VERSION@", version)))
    written.append(write(os.path.join(PY_OUT, "blochclient", "py.typed"), ""))
    written.append(write(os.path.join(PY_OUT, "pyproject.toml"), PY_PYPROJECT.replace("@VERSION@", version)))
    written.append(write(os.path.join(PY_OUT, "README.md"), PY_README))
    written.append(write(os.path.join(PY_OUT, ".gitignore"), PY_GITIGNORE))
    written.append(write(os.path.join(PY_OUT, "LICENSE-MIT"), LICENSE_MIT))
    written.append(write(os.path.join(PY_OUT, "LICENSE-APACHE"), LICENSE_APACHE))

    # ── Go module ──
    written.append(write(os.path.join(GO_OUT, "models.go"), build_go_models(schemas)))
    written.append(write(os.path.join(GO_OUT, "client.go"), build_go_client(methods)))
    written.append(write(os.path.join(GO_OUT, "errors.go"), GO_ERRORS))
    written.append(write(os.path.join(GO_OUT, "units.go"), GO_UNITS))
    written.append(write(os.path.join(GO_OUT, "satoshis.go"), GO_SATOSHIS))
    written.append(write(os.path.join(GO_OUT, "satoshis_test.go"), GO_SATOSHIS_TEST))
    written.append(write(os.path.join(GO_OUT, "signer.go"), GO_SIGNER))
    written.append(write(os.path.join(GO_OUT, "doc.go"), GO_DOC))
    written.append(write(os.path.join(GO_OUT, "go.mod"), GO_MOD.replace("@VERSION@", version)))
    written.append(write(os.path.join(GO_OUT, "README.md"), GO_README))
    written.append(write(os.path.join(GO_OUT, ".gitignore"), GO_GITIGNORE))
    written.append(write(os.path.join(GO_OUT, "LICENSE-MIT"), LICENSE_MIT))
    written.append(write(os.path.join(GO_OUT, "LICENSE-APACHE"), LICENSE_APACHE))

    # ── Codegen README ──
    written.append(write(os.path.join(HERE, "README.md"), CODEGEN_README))

    formatted = gofmt(written)

    n_models = sum(1 for n in schemas if n not in SKIP_SCHEMAS and n not in SCALAR_ALIASES)
    print(f"Bloch SDK generator — spec: {SPEC_REL} (v{version})")
    print(f"  schemas: {len(schemas)} (skipped {len(SKIP_SCHEMAS)} envelope types)")
    print(f"  emitted models: {n_models} + {len(SYNTHETICS)} synthetic + {len(SCALAR_ALIASES)} scalar aliases")
    print(f"  methods: {len(methods)} typed wrappers per client")
    print(f"  wrote {len(written)} files under sdk/python/ and sdk/go/")
    print("  gofmt: " + ("applied" if formatted else "skipped (gofmt not on PATH)"))


if __name__ == "__main__":
    main()
