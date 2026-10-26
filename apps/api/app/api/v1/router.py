from fastapi import APIRouter

from app.api.v1.routes import (
    analyses,
    content_inspections,
    epss_intelligence,
    fingerprints,
    health,
    kev_intelligence,
    ml_inferences,
    static_analyses,
    uploads,
    vulnerabilities,
)

api_router = APIRouter()

api_router.include_router(health.router)
api_router.include_router(kev_intelligence.router)
api_router.include_router(epss_intelligence.router)
api_router.include_router(analyses.router)
api_router.include_router(uploads.router)
api_router.include_router(fingerprints.router)
api_router.include_router(content_inspections.router)
api_router.include_router(static_analyses.router)
api_router.include_router(ml_inferences.router)
api_router.include_router(vulnerabilities.router)
