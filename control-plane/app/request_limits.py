"""Request body size guard for endpoints that accept user-supplied structures.

FastAPI reads and parses a JSON body before any dependency runs, so a size check
on a normal ``body: Model`` parameter comes too late. ``limited_json_body(Model)``
reads the raw body itself, rejects it with a 413 once it exceeds the limit
(checking Content-Length first, then counting streamed bytes, since clients can
omit or misstate the header), and only then validates it into the model.

Usage::

    @router.post("/ingest", openapi_extra=json_body_openapi(Model))
    def ingest(body: Model = Depends(limited_json_body(Model))): ...
"""

import os

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ValidationError

DEFAULT_MAX_REQUEST_BODY_MB = 20


def max_request_body_bytes() -> int:
    """Limit from KAAVAL_MAX_REQUEST_BODY_MB, read per request so tests and operators can change it."""
    value = int(os.getenv("KAAVAL_MAX_REQUEST_BODY_MB", DEFAULT_MAX_REQUEST_BODY_MB))
    if value <= 0:
        raise ValueError("KAAVAL_MAX_REQUEST_BODY_MB must be a positive integer")
    return value * 1024 * 1024


def _too_large(limit: int) -> HTTPException:
    return HTTPException(
        status_code=413,
        detail=f"Request body exceeds the {limit // (1024 * 1024)} MB limit (KAAVAL_MAX_REQUEST_BODY_MB).",
    )


async def read_body_with_limit(request: Request, limit: int) -> bytes:
    """Return the raw request body, raising 413 as soon as it is known to exceed ``limit`` bytes."""
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            length = int(content_length)
            if length < 0:
                raise ValueError
            if length > limit:
                raise _too_large(limit)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header.")

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > limit:
            raise _too_large(limit)
        body.extend(chunk)
    return bytes(body)


def limited_json_body(model: type[BaseModel]):
    """Dependency that parses the JSON body into ``model`` after enforcing the size limit."""

    async def dependency(request: Request) -> BaseModel:
        raw = await read_body_with_limit(request, max_request_body_bytes())
        try:
            return model.model_validate_json(raw)
        except ValidationError as ex:
            errors = ex.errors(include_url=False, include_input=False, include_context=False)
            for error in errors:
                error["loc"] = ("body", *error["loc"])
            raise RequestValidationError(errors)

    return dependency


def json_body_openapi(model: type[BaseModel]) -> dict:
    """``openapi_extra`` that keeps the request body schema in /docs for a limited_json_body route."""
    schema = model.model_json_schema()
    definitions = schema.pop("$defs", {})

    # Pydantic's #/$defs references point at the document root. Inline nested
    # report models because this schema lives inside an OpenAPI operation.
    def inline(value):
        if isinstance(value, list):
            return [inline(item) for item in value]
        if isinstance(value, dict):
            if "$ref" in value:
                return inline(definitions[value["$ref"].rsplit("/", 1)[1]])
            return {key: inline(item) for key, item in value.items()}
        return value

    return {
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": inline(schema)}},
        }
    }
