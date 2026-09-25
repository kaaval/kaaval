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
    return int(os.getenv("KAAVAL_MAX_REQUEST_BODY_MB", DEFAULT_MAX_REQUEST_BODY_MB)) * 1024 * 1024


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
            if int(content_length) > limit:
                raise _too_large(limit)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header.")

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise _too_large(limit)
    return bytes(body)


def limited_json_body(model: type[BaseModel]):
    """Dependency that parses the JSON body into ``model`` after enforcing the size limit."""

    async def dependency(request: Request) -> BaseModel:
        raw = await read_body_with_limit(request, max_request_body_bytes())
        try:
            return model.model_validate_json(raw or b"{}")
        except ValidationError as ex:
            raise RequestValidationError(ex.errors(include_url=False))

    return dependency


def json_body_openapi(model: type[BaseModel]) -> dict:
    """``openapi_extra`` that keeps the request body schema in /docs for a limited_json_body route."""
    return {
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": model.model_json_schema()}},
        }
    }
