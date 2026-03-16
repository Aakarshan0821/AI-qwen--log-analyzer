import logging
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.config import Settings, get_settings
from app.errors import AppError
from app.services.auto_analysis_service import (
    load_auto_analysis_config,
    sync_auto_analysis_scheduler,
)
from app.state import initialize_state

logger = logging.getLogger(__name__)


def _register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(_: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.message, "code": exc.code},
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled server error", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={
                "detail": "服务器内部错误，请稍后重试并检查后端日志。",
                "code": "internal_server_error",
            },
        )


def create_app() -> FastAPI:
    settings = get_settings()
    auto_analysis_config = load_auto_analysis_config(settings)
    app = FastAPI(title="Defence App", version="1.2.0")
    app.state.settings = settings
    app.state.auto_analysis_config = auto_analysis_config
    app.state.scheduler = AsyncIOScheduler()

    static_dir = Path(__file__).resolve().parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    app.include_router(router)
    _register_exception_handlers(app)
    initialize_state(auto_analysis_config["interval_minutes"])

    @app.on_event("startup")
    async def startup_event() -> None:
        await sync_auto_analysis_scheduler(app, run_immediately=True)

    @app.on_event("shutdown")
    async def shutdown_event() -> None:
        scheduler: AsyncIOScheduler = app.state.scheduler
        if scheduler.running:
            scheduler.shutdown(wait=False)

    return app
