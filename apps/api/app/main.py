import logging
from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI

from app.api.v1.router import api_router
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.integrations.nvd.client import NVDClient
from app.ml.demo import initialize_synthetic_demo
from app.ml.model_runtime import TrustedModelRuntime
from app.schemas.ml_inference import ActiveModelDescriptor
from app.services.ml_inference import InferenceCapacity

logger = logging.getLogger("icylens.ml_lifecycle")

ModelInitializer = Callable[[TrustedModelRuntime], ActiveModelDescriptor]
NVDClientFactory = Callable[[Settings], NVDClient]


def create_app(
    settings: Settings | None = None,
    *,
    model_initializer: ModelInitializer | None = None,
    nvd_client_factory: NVDClientFactory | None = None,
) -> FastAPI:
    resolved_settings = settings or get_settings()
    configure_logging(resolved_settings.LOG_LEVEL)
    runtime = TrustedModelRuntime()
    initializer = model_initializer or initialize_synthetic_demo
    create_nvd_client = nvd_client_factory or NVDClient

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        nvd_client = create_nvd_client(resolved_settings)
        application.state.nvd_client = nvd_client
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
