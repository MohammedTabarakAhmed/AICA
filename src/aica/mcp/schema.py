"""Build a validating argument model from a server's JSON Schema (MCP-003).

An MCP server advertises each tool's inputs as JSON Schema. Arguments must be validated
against it *before* anything is sent, for the same reason built-in tools validate with
pydantic: a malformed call should fail here, with a readable message, rather than reaching
someone else's process.

The schema comes from a third party, so this converter is defensive: it handles the subset
real servers use, refuses schemas that are too deep or too wide to be reasonable, and falls
back to a permissive field rather than guessing when it meets something it does not model.
A permissive field still goes through pydantic - it just accepts any JSON value.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, create_model
from pydantic.config import ExtraValues

MAX_PROPERTIES = 100
MAX_DEPTH = 6

_SIMPLE_TYPES: dict[str, Any] = {
    "string": str,
    "integer": int,
    "number": float,
    "boolean": bool,
    "array": list,
    "object": dict,
    "null": type(None),
}


class SchemaError(ValueError):
    """The advertised schema cannot be turned into a usable argument model."""


def _annotation(spec: dict[str, Any], depth: int) -> Any:
    if depth > MAX_DEPTH:
        return Any
    if "enum" in spec and isinstance(spec["enum"], list) and spec["enum"]:
        values = [v for v in spec["enum"] if isinstance(v, str | int | float | bool)]
        if values and len(values) == len(spec["enum"]):
            return Literal[tuple(values)]
        return Any
    raw_type = spec.get("type")
    if isinstance(raw_type, list):
        # A union such as ["string", "null"]: model the non-null member as optional.
        members = [t for t in raw_type if t != "null"]
        if len(members) == 1 and members[0] in _SIMPLE_TYPES:
            return _SIMPLE_TYPES[members[0]] | None
        return Any
    if raw_type == "array":
        items = spec.get("items")
        if isinstance(items, dict):
            return list[_annotation(items, depth + 1)]  # type: ignore[misc]
        return list[Any]
    if raw_type == "object":
        return dict[str, Any]
    if isinstance(raw_type, str) and raw_type in _SIMPLE_TYPES:
        return _SIMPLE_TYPES[raw_type]
    return Any


def model_from_schema(name: str, schema: dict[str, Any] | None) -> type[BaseModel]:
    """Turn a tool's ``inputSchema`` into a pydantic model (MCP-003).

    A tool with no schema, or a schema that is not an object, gets a model that accepts any
    keyword arguments: the server did not state a contract, so this layer cannot invent one,
    and the server is responsible for rejecting what it does not like.
    """
    model_name = "".join(part.capitalize() for part in name.replace(".", "_").split("_")) or "Args"
    if not isinstance(schema, dict) or schema.get("type") not in (None, "object"):
        return create_model(f"{model_name}Args", __config__=ConfigDict(extra="allow"))

    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return create_model(f"{model_name}Args", __config__=ConfigDict(extra="allow"))
    if len(properties) > MAX_PROPERTIES:
        raise SchemaError(
            f"tool {name!r} advertises {len(properties)} properties; the maximum is "
            f"{MAX_PROPERTIES}"
        )

    required = schema.get("required")
    required_names = set(required) if isinstance(required, list) else set()
    # additionalProperties defaults to permitted in JSON Schema, but a tool call is not a
    # document: an unexpected argument is far more likely to be a mistake than an extension.
    extra: ExtraValues = "forbid" if schema.get("additionalProperties") is not True else "allow"

    fields: dict[str, Any] = {}
    for key, spec in properties.items():
        if not isinstance(key, str) or not key.isidentifier():
            # A field name pydantic cannot express: fall back to accepting anything.
            return create_model(f"{model_name}Args", __config__=ConfigDict(extra="allow"))
        spec = spec if isinstance(spec, dict) else {}
        annotation = _annotation(spec, 1)
        description = spec.get("description")
        description = description if isinstance(description, str) else None
        if key in required_names and "default" not in spec:
            fields[key] = (annotation, Field(description=description))
        else:
            fields[key] = (
                annotation | None if annotation is not Any else Any,
                Field(default=spec.get("default"), description=description),
            )
    return create_model(
        f"{model_name}Args",
        __config__=ConfigDict(extra=extra),
        **fields,
    )
