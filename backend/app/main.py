
"""FastAPI application entrypoint for the Hybrid AI WAF."""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import logging
from typing import AsyncGenerator

import uvicorn
from fastapi import FastAPI, Request, Response

from app.config import (
    WAF_HOST,
    WAF_PORT,
    SYSTEM_STATUS_PATH,
)
from app.proxy import WAFReverseProxy

# Import the actual hybrid detector.
from detector import detect, _load_model, MODEL_PATH

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger("waf.main")


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def write_system_status(waf_status: str) -> dict:
    """Write truthful WAF, detection-engine and ML-model status."""

    detection_engine = "ONLINE"
    ml_model = "NOT_LOADED"
    model_details = {
        "algorithm": "Hybrid Rule-Based + ML Classifier",
        "model_path": str(MODEL_PATH),
        "training_status": "UNKNOWN",
    }

    try:
        # Confirm the actual detector is callable.
        if not callable(detect):
            detection_engine = "UNAVAILABLE"
    except Exception:
        detection_engine = "UNAVAILABLE"

    try:
        # Check the actual model-loading result.
        model = _load_model()

        if model is not None:
            ml_model = "LOADED"
            model_details["training_status"] = "LOADED"
        elif not MODEL_PATH.is_file():
            ml_model = "MISSING"
            model_details["training_status"] = "MODEL FILE MISSING"
        else:
            ml_model = "LOAD_FAILED"
            model_details["training_status"] = "MODEL LOAD FAILED"

    except Exception as exc:
        ml_model = "LOAD_FAILED"
        model_details["training_status"] = str(exc)
        logger.exception("Unable to inspect ML model status")

    if detection_engine == "UNAVAILABLE":
        waf_status = "DEGRADED"

    status = {
        "last_updated": utc_now(),
        "waf_status": waf_status,
        "detection_engine": detection_engine,
        "ml_model": ml_model,
        "components": {
            "reverse_proxy": waf_status,
            "detection_adapter": detection_engine,
            "hybrid_detector": detection_engine,
            "ml_model": ml_model,
        },
        "model": model_details,
    }

    try:
        SYSTEM_STATUS_PATH.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        temporary_path = SYSTEM_STATUS_PATH.with_suffix(".tmp")
        temporary_path.write_text(
            json.dumps(status, indent=4),
            encoding="utf-8",
        )
        temporary_path.replace(SYSTEM_STATUS_PATH)

        logger.info(
            "System status updated: WAF=%s, Detection=%s, ML=%s",
            waf_status,
            detection_engine,
            ml_model,
        )

    except OSError:
        logger.exception("Could not write system status file")

    return status


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage WAF startup and shutdown."""

    logger.info("Initializing Hybrid AI WAF...")

    app.state.proxy = WAFReverseProxy()
    app.state.system_status = write_system_status("ONLINE")

    yield

    logger.info("Shutting down Hybrid AI WAF...")
    write_system_status("OFFLINE")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    application = FastAPI(
        title="Hybrid AI WAF Reverse Proxy",
        description="Reverse proxy with hybrid threat detection",
        version="0.1.0",
        lifespan=lifespan,
    )

    @application.get("/health", tags=["Health"])
    async def health_check() -> dict:
        """Return current WAF system health."""

        status = write_system_status("ok")
        application.state.system_status = status

        return {
            "status": status["waf_status"],
            "service": "waf-proxy",
            "version": "0.1.0",
            "detection_engine": status["detection_engine"],
            "ml_model": status["ml_model"],
            "last_updated": status["last_updated"],
        }

    HTTP_METHODS = [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD",
    ]

    @application.api_route(
        "/",
        methods=HTTP_METHODS,
        include_in_schema=False,
    )
    async def proxy_root(request: Request) -> Response:
        return await application.state.proxy.handle_request(
            request,
            path="",
        )

    @application.api_route(
        "/{path:path}",
        methods=HTTP_METHODS,
        include_in_schema=False,
    )
    async def proxy_catch_all(
        request: Request,
        path: str,
    ) -> Response:
        return await application.state.proxy.handle_request(
            request,
            path=path,
        )

    return application


app = create_app()


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=WAF_HOST,
        port=WAF_PORT,
        reload=False,
    )
