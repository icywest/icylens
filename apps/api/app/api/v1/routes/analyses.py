from fastapi import APIRouter

from app.schemas.analysis import AnalysisRequest

router = APIRouter(
    prefix="/analyses",
    tags=["Analyses"],
)


@router.post(
    "/validate",
    response_model=AnalysisRequest,
    summary="Validate an analysis request",
)
def validate_analysis_request(
    request: AnalysisRequest,
) -> AnalysisRequest:
    return request
