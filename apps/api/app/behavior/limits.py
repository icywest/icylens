from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.schemas.behavior import MAX_BATCH_BYTES, MAX_GENERATION_BODY_BYTES


class _BodyTooLarge(Exception):
    pass


class BehaviorBodyLimitMiddleware:
    """Reject oversized behavior bodies before FastAPI buffers or validates them."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    @staticmethod
    def _limit(scope: Scope) -> int | None:
        path = str(scope.get("path", ""))
        if path.endswith("/behavior/events/validate"):
            return MAX_BATCH_BYTES
        if path.endswith("/behavior/scenarios/generate"):
            return MAX_GENERATION_BODY_BYTES
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or (limit := self._limit(scope)) is None:
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError:
                await JSONResponse(
                    {"detail": "Invalid Content-Length header."}, status_code=400
                )(scope, receive, send)
                return
            if length < 0:
                await JSONResponse(
                    {"detail": "Invalid Content-Length header."}, status_code=400
                )(scope, receive, send)
                return
            if length > limit:
                await JSONResponse(
                    {"detail": "Request body is too large."}, status_code=413
                )(scope, receive, send)
                return

        observed = 0

        async def limited_receive() -> Message:
            nonlocal observed
            message = await receive()
            if message["type"] == "http.request":
                observed += len(message.get("body", b""))
                if observed > limit:
                    raise _BodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await JSONResponse(
                {"detail": "Request body is too large."}, status_code=413
            )(scope, receive, send)
