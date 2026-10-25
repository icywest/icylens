from fastapi import APIRouter

from app.api.v1.routes import (
    analyses,
    content_inspections,
    fingerprints,
    health,
    static_analyses,
    uploads,
)

api_router = APIRouter()

api_router.include_router(health.router)
api_router.include_router(analyses.router)
api_router.include_router(uploads.router)
api_router.include_router(fingerprints.router)
api_router.include_router(content_inspections.router)
api_router.include_router(static_analyses.router)
