from typing import Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: Literal["healthy"] = Field(description="Current process health state.")
    service: str = Field(description="Configured application name.")
    version: str = Field(description="Configured application version.")
    message: str = Field(description="Human-readable operational message.")
