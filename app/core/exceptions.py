"""
GHOSTSENTINEL Ω — Centralised Exception Handling
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from app.core.logging_config import get_logger

logger = get_logger(__name__)


class GhostSentinelError(Exception):
    """Base application error."""
    def __init__(self, message: str, status_code: int = 500):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class ScanError(GhostSentinelError):
    """Raised when a scan operation fails."""
    def __init__(self, message: str):
        super().__init__(message, status_code=422)


class PermissionError_(GhostSentinelError):
    """Raised when privileges are insufficient."""
    def __init__(self, message: str):
        super().__init__(message, status_code=403)


class HardwareNotAvailableError(GhostSentinelError):
    """Raised when required hardware is absent or unsupported."""
    def __init__(self, message: str):
        super().__init__(message, status_code=503)


class ScopeViolationError(GhostSentinelError):
    """Raised when a scan target is outside the authorised scope."""
    def __init__(self, message: str):
        super().__init__(message, status_code=403)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(GhostSentinelError)
    async def ghostsentinel_error_handler(request: Request, exc: GhostSentinelError):
        logger.error("Application error: %s", exc.message)
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.message, "type": type(exc).__name__},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content={"error": "An unexpected internal error occurred.", "type": "InternalError"},
        )
