"""Reverse Proxy Engine for WAF.

Intercepts all HTTP traffic, extracts request metadata, coordinates detection,
blocks malicious requests with HTTP 403, and asynchronously forwards allowed traffic
to the configured upstream server (DVWA).
"""

from typing import Dict, Optional, Tuple
import logging
from urllib.parse import urljoin

from fastapi import Request, Response
import httpx

from app.config import UPSTREAM_TIMEOUT, UPSTREAM_URL
from app.detection_adapter import DetectionAdapter, default_adapter
from app.event_logger import EventLogger, default_event_logger

logger = logging.getLogger("waf.proxy")

# Standard Hop-by-hop headers that should not be forwarded
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


class WAFReverseProxy:
    """Core reverse proxy controller."""

    def __init__(
        self,
        upstream_url: Optional[str] = None,
        timeout: Optional[float] = None,
        adapter: Optional[DetectionAdapter] = None,
        event_logger: Optional[EventLogger] = None,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        self.upstream_url = (upstream_url or UPSTREAM_URL).rstrip("/")
        self.timeout = timeout or UPSTREAM_TIMEOUT
        self.adapter = adapter or default_adapter
        self.event_logger = event_logger or default_event_logger
        self._custom_client = http_client

    def _get_client_ip(self, request: Request) -> str:
        """Extracts client IP address safely."""
        if request.client and request.client.host:
            return request.client.host
        # Fallback to header if running behind an L4/L7 load balancer
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return "127.0.0.1"

    def _sanitize_request_headers(self, request: Request, client_ip: str) -> Dict[str, str]:
        """Strips hop-by-hop headers and adds standard forwarding metadata."""
        forward_headers: Dict[str, str] = {}
        for key, value in request.headers.items():
            lower_key = key.lower()
            if lower_key in HOP_BY_HOP_HEADERS:
                continue
            # Do not forward proxy host header as upstream host
            if lower_key == "host":
                continue
            forward_headers[key] = value

        # Set standard forward headers
        forward_headers["X-Forwarded-For"] = client_ip
        forward_headers["X-Forwarded-Proto"] = request.url.scheme
        if "host" in request.headers:
            forward_headers["X-Forwarded-Host"] = request.headers["host"]

        return forward_headers

    def _sanitize_response_headers(self, upstream_headers: httpx.Headers) -> Dict[str, str]:
        """Cleans upstream response headers before returning to client."""
        clean_headers: Dict[str, str] = {}
        # Strip hop-by-hop headers and transport-specific headers managed by ASGI server
        excluded = HOP_BY_HOP_HEADERS | {"content-length", "content-encoding"}
        for key, value in upstream_headers.items():
            if key.lower() not in excluded:
                clean_headers[key] = value
        return clean_headers

    async def handle_request(self, request: Request, path: str) -> Response:
        """Main pipeline: extract -> detect -> log -> block or forward."""
        client_ip = self._get_client_ip(request)
        method = request.method
        path_str = f"/{path.lstrip('/')}"
        query_str = request.url.query

        # Read raw body bytes and decode for detection inspection
        body_bytes = await request.body()
        body_str = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""

        # Construct contract request payload for detection
        req_contract = {
            "method": method,
            "path": path_str,
            "query": query_str,
            "body": body_str,
            "headers": dict(request.headers),
        }

        # 1. Execute detection with fail-safe adapter
        detection_result = await self.adapter.detect(req_contract)
        verdict = detection_result.get("verdict", "block")
        attack_type = detection_result.get("attack_type", "none")
        score = detection_result.get("score", 0.0)
        reason = detection_result.get("reason", "")

        # 2. Extract payload strictly following policy: body > query > ""
        extracted_payload = self.event_logger.extract_payload(body_str, query_str)

        # 3. Log event (for BOTH allowed and blocked requests)
        event_record = self.event_logger.create_event_record(
            ip=client_ip,
            method=method,
            path=path_str,
            payload=extracted_payload,
            verdict=verdict,
            attack_type=attack_type,
            score=score,
        )
        await self.event_logger.log_event(event_record)

        # 4. Enforce verdict: Block malicious requests with HTTP 403
        if verdict == "block":
            logger.warning(
                "BLOCKED %s %s from %s [attack_type=%s, score=%s, reason=%s]",
                method, path_str, client_ip, attack_type, score, reason
            )
            return Response(
                content=f'{{"detail":"Forbidden: Request blocked by WAF","attack_type":"{attack_type}","reason":"{reason}"}}',
                status_code=403,
                media_type="application/json",
            )

        # 5. Forward allowed traffic to upstream asynchronously
        upstream_target = f"{self.upstream_url}{path_str}"
        if query_str:
            upstream_target = f"{upstream_target}?{query_str}"

        forward_headers = self._sanitize_request_headers(request, client_ip)

        try:
            if self._custom_client:
                upstream_resp = await self._custom_client.request(
                    method=method,
                    url=upstream_target,
                    content=body_bytes if body_bytes else None,
                    headers=forward_headers,
                    timeout=self.timeout,
                )
            else:
                async with httpx.AsyncClient() as client:
                    upstream_resp = await client.request(
                        method=method,
                        url=upstream_target,
                        content=body_bytes if body_bytes else None,
                        headers=forward_headers,
                        timeout=self.timeout,
                    )

            clean_headers = self._sanitize_response_headers(upstream_resp.headers)
            return Response(
                content=upstream_resp.content,
                status_code=upstream_resp.status_code,
                headers=clean_headers,
                media_type=upstream_resp.headers.get("content-type"),
            )

        except (httpx.ConnectError, httpx.NetworkError) as conn_err:
            logger.error("Upstream connection failure for %s: %s", upstream_target, conn_err)
            return Response(
                content='{"detail":"502 Bad Gateway: Upstream connection failed"}',
                status_code=502,
                media_type="application/json",
            )
        except httpx.TimeoutException as timeout_err:
            logger.error("Upstream timeout for %s: %s", upstream_target, timeout_err)
            return Response(
                content='{"detail":"504 Gateway Timeout: Upstream request timed out"}',
                status_code=504,
                media_type="application/json",
            )
        except httpx.HTTPError as http_err:
            logger.error("Upstream HTTP error for %s: %s", upstream_target, http_err)
            return Response(
                content='{"detail":"502 Bad Gateway: Error communicating with upstream server"}',
                status_code=502,
                media_type="application/json",
            )
