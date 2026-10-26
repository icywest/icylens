import json

from fastapi import HTTPException, Request
from pydantic import ValidationError

from app.schemas.vulnerability_interpretation import AssetInventory


async def read_asset_inventory(request: Request) -> AssetInventory:
    maximum = request.app.state.settings.VULNERABILITY_MAX_INVENTORY_BODY_BYTES
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > maximum:
                raise HTTPException(413, "Asset inventory body is too large.")
        except ValueError as error:
            raise HTTPException(400, "Invalid Content-Length header.") from error
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > maximum:
            raise HTTPException(413, "Asset inventory body is too large.")
    try:
        payload = json.loads(bytes(body))
        return AssetInventory.model_validate(payload)
    except (
        json.JSONDecodeError,
        UnicodeDecodeError,
        ValidationError,
        TypeError,
    ) as error:
        raise HTTPException(422, "Invalid asset inventory.") from error
