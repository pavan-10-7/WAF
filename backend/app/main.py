"""FastAPI Reverse Proxy Application Entrypoint for WAF."""

from contextlib import asynccontextmanager
import logging
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Response
import uvicorn

from app.config import WAF_HOST, WAF_PORT
from app.proxy import WAFReverseProxy

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("waf.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manages application startup and shutdown lifecycle."""
    logger.info("Initializing WAF Reverse Proxy...")
    if not hasattr(app.state, "proxy"):
        app.state.proxy = WAFReverseProxy()
    yield
    logger.info("WAF Reverse Proxy shutting down.")


def create_app() -> FastAPI:
    """Factory creating and configuring the FastAPI WAF reverse proxy app."""
    application = FastAPI(
        title="Hybrid AI WAF Reverse Proxy",
        description="FastAPI Reverse Proxy with Detection and Event Logging",
        version="0.1.0",
        lifespan=lifespan,
    )
    application.state.proxy = WAFReverseProxy()

    @application.get("/health", tags=["Health"])
    async def health_check() -> dict:
        """Health check endpoint for proxy monitoring."""
        return {
            "status": "ok",
            "service": "waf-proxy",
            "version": "0.1.0",
        }

    # Catch-all routes covering root path and nested paths
    HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

    @application.api_route("/", methods=HTTP_METHODS, include_in_schema=False)
    async def proxy_root(request: Request) -> Response:
        proxy: WAFReverseProxy = application.state.proxy
        return await proxy.handle_request(request, path="")

    @application.api_route("/{path:path}", methods=HTTP_METHODS, include_in_schema=False)
    async def proxy_catch_all(request: Request, path: str) -> Response:
        proxy: WAFReverseProxy = application.state.proxy
        return await proxy.handle_request(request, path=path)

    return application


app = create_app()

if __name__ == "__main__":
    uvicorn.run("app.main:app", host=WAF_HOST, port=WAF_PORT, reload=False)
