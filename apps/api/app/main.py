import logging
from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI

from app.api.v1.router import api_router
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.integrations.cisa_kev.client import KEVClient, KEVClientError
from app.integrations.first_epss.client import EPSSClient
from app.integrations.nvd.client import NVDClient
from app.intelligence.kev_catalog import KEVCatalogStore, KEVCatalogValidationError
from app.ml.demo import initialize_synthetic_demo
from app.ml.model_runtime import TrustedModelRuntime
from app.schemas.ml_inference import ActiveModelDescriptor
from app.services.epss_intelligence import EPSSIntelligenceService
from app.services.ml_inference import InferenceCapacity

logger = logging.getLogger("icylens.ml_lifecycle")
kev_logger = logging.getLogger("icylens.kev_lifecycle")

ModelInitializer = Callable[[TrustedModelRuntime], ActiveModelDescriptor]
NVDClientFactory = Callable[[Settings], NVDClient]
KEVClientFactory = Callable[[Settings], KEVClient]
KEVStoreFactory = Callable[[Settings], KEVCatalogStore]
EPSSClientFactory = Callable[[Settings], EPSSClient]


def create_app(
    settings: Settings | None = None,
    *,
    model_initializer: ModelInitializer | None = None,
    nvd_client_factory: NVDClientFactory | None = None,
    kev_client_factory: KEVClientFactory | None = None,
    kev_store_factory: KEVStoreFactory | None = None,
    epss_client_factory: EPSSClientFactory | None = None,
) -> FastAPI:
    resolved_settings = settings or get_settings()
    configure_logging(resolved_settings.LOG_LEVEL)
    runtime = TrustedModelRuntime()
    initializer = model_initializer or initialize_synthetic_demo
    create_nvd_client = nvd_client_factory or NVDClient
    create_kev_client = kev_client_factory or KEVClient
    create_kev_store = kev_store_factory or KEVCatalogStore
    create_epss_client = epss_client_factory or EPSSClient

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        nvd_client = create_nvd_client(resolved_settings)
        kev_client = create_kev_client(resolved_settings)
        kev_store = create_kev_store(resolved_settings)
        epss_client = create_epss_client(resolved_settings)
        application.state.nvd_client = nvd_client
        application.state.kev_client = kev_client
        application.state.kev_store = kev_store
        application.state.epss_service = EPSSIntelligenceService(
            resolved_settings, epss_client
        )
        if resolved_settings.KEV_REFRESH_ON_STARTUP:
            try:
                await kev_store.refresh(kev_client)
            except (KEVClientError, KEVCatalogValidationError) as exc:
                kev_logger.warning(
                    "CISA KEV startup refresh failed with exception type %s",
                    type(exc).__name__,
                )
            except Exception as exc:
                kev_logger.error(
                    "CISA KEV startup refresh failed with exception type %s",
                    type(exc).__name__,
                )
        if (
            resolved_settings.ML_INFERENCE_ENABLED
            and resolved_settings.ML_DEMO_MODE_ENABLED
        ):
            try:
                initializer(runtime)
            except Exception as exc:
                runtime.reject()
                logger.error(
                    "ML demo initialization failed with exception type %s",
                    type(exc).__name__,
                )
        try:
            yield
        finally:
            await epss_client.aclose()
            await kev_client.aclose()
            await nvd_client.aclose()
            runtime.revoke()

    application = FastAPI(
        title=resolved_settings.APP_NAME,
        description=(
            "Intelligent Cybersecurity Analysis Platform. "
            "Educational backend for threat analysis, "
            "machine learning, and vulnerability intelligence."
        ),
        version=resolved_settings.APP_VERSION,
        debug=resolved_settings.DEBUG,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    application.state.settings = resolved_settings
    application.state.ml_runtime = runtime
    application.state.ml_inference_capacity = InferenceCapacity(
        resolved_settings.ML_MAX_CONCURRENT_INFERENCES
    )

    application.include_router(
        api_router,
        prefix=resolved_settings.API_V1_PREFIX,
    )

    return application


app = create_app()
