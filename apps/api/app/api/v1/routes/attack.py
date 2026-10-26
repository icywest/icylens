import logging
from typing import Annotated, cast

from fastapi import APIRouter, HTTPException, Path, Query, Request, status

from app.attack.catalog import ATTACKCatalogStore, ATTACKCatalogUnavailableError
from app.schemas.attack import (
    ATTACKCatalogStatus,
    ATTACKTactic,
    ATTACKTacticList,
    ATTACKTechnique,
    ATTACKTechniqueList,
)
from app.services.attack_knowledge import ATTACKKnowledgeService

logger = logging.getLogger("icylens.attack")
router = APIRouter(prefix="/attack", tags=["MITRE ATT&CK Knowledge"])
TacticId = Annotated[str, Path(pattern=r"^TA[0-9]{4}$", max_length=6)]
TechniqueId = Annotated[str, Path(pattern=r"^T[0-9]{4}(?:\.[0-9]{3})?$", max_length=9)]
Offset = Annotated[int, Query(ge=0, le=100_000)]
Limit = Annotated[int, Query(ge=1, le=200)]


def _service(request: Request) -> ATTACKKnowledgeService:
    return ATTACKKnowledgeService(
        cast(ATTACKCatalogStore, request.app.state.attack_store)
    )


def _handle_lookup(
    request: Request, function: str, attack_id: str, include_retired: bool
) -> ATTACKTactic | ATTACKTechnique:
    try:
        service = _service(request)
        item = (
            service.tactic(attack_id, include_retired)
            if function == "tactic"
            else service.technique(attack_id, include_retired)
        )
        if item is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, "ATT&CK identifier was not found."
            )
        return item
    except ATTACKCatalogUnavailableError as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "ATT&CK catalog is not available."
        ) from error
    except HTTPException:
        raise
    except Exception as error:
        logger.error(
            "ATT&CK lookup failed with exception type %s", type(error).__name__
        )
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "ATT&CK lookup could not be completed.",
        ) from None


@router.get("/status", response_model=ATTACKCatalogStatus)
def get_status(request: Request) -> ATTACKCatalogStatus:
    return _service(request).status()


@router.get("/tactics", response_model=ATTACKTacticList)
def list_tactics(
    request: Request,
    offset: Offset = 0,
    limit: Limit = 50,
    include_retired: bool = False,
) -> ATTACKTacticList:
    try:
        return _service(request).tactics(offset, limit, include_retired)
    except ATTACKCatalogUnavailableError as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "ATT&CK catalog is not available."
        ) from error


@router.get("/tactics/{tactic_id}", response_model=ATTACKTactic)
def get_tactic(
    request: Request, tactic_id: TacticId, include_retired: bool = False
) -> ATTACKTactic:
    return cast(
        ATTACKTactic, _handle_lookup(request, "tactic", tactic_id, include_retired)
    )


@router.get("/tactics/{tactic_id}/techniques", response_model=ATTACKTechniqueList)
def list_tactic_techniques(
    request: Request,
    tactic_id: TacticId,
    offset: Offset = 0,
    limit: Limit = 100,
    include_retired: bool = False,
) -> ATTACKTechniqueList:
    service = _service(request)
    try:
        if service.tactic(tactic_id, include_retired) is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, "ATT&CK tactic was not found."
            )
        return service.techniques_for_tactic(tactic_id, offset, limit, include_retired)
    except ATTACKCatalogUnavailableError as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "ATT&CK catalog is not available."
        ) from error


@router.get("/techniques/{technique_id}", response_model=ATTACKTechnique)
def get_technique(
    request: Request, technique_id: TechniqueId, include_retired: bool = False
) -> ATTACKTechnique:
    return cast(
        ATTACKTechnique,
        _handle_lookup(request, "technique", technique_id, include_retired),
    )


@router.get(
    "/techniques/{technique_id}/subtechniques", response_model=ATTACKTechniqueList
)
def list_subtechniques(
    request: Request,
    technique_id: TechniqueId,
    offset: Offset = 0,
    limit: Limit = 100,
    include_retired: bool = False,
) -> ATTACKTechniqueList:
    service = _service(request)
    try:
        parent = service.technique(technique_id, include_retired)
        if parent is None or parent.is_subtechnique:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, "ATT&CK parent technique was not found."
            )
        return service.subtechniques(technique_id, offset, limit, include_retired)
    except ATTACKCatalogUnavailableError as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "ATT&CK catalog is not available."
        ) from error
