from fastapi import FastAPI

from app.api.v1.router import api_router
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or get_settings()
    configure_logging(resolved_settings.LOG_LEVEL)

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
    )
    application.state.settings = resolved_settings

    application.include_router(
        api_router,
        prefix=resolved_settings.API_V1_PREFIX,
    )

    return application


app = create_app()
