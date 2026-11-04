"""FastAPI control plane for :mod:`qkd_kms.simulator`."""

from __future__ import annotations
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Deque, Dict, Optional
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, StrictBool, model_validator
from .simulator import MockKmsService, RateModelConfig
from .simulator import MAX_BUFFER_CAPACITY_BYTES

SESSION_COOKIE = "linqkd_kms_session"
PRESET_ID_PATTERN = re.compile("^[a-z0-9][a-z0-9-]{0,63}$")


class LoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


class ConfigurationRequest(BaseModel):
    average_rate_bytes_per_second: float = Field(ge=0, le=1000000000)
    variation_percent: float = Field(ge=0, le=300)
    fluctuation_interval_seconds: float = Field(ge=0.1, le=3600)
    smoothing: float = Field(ge=0, le=0.99)
    minimum_rate_bytes_per_second: float = Field(ge=0, le=1000000000)
    dropout_chance_per_minute: float = Field(ge=0, le=1)
    dropout_duration_seconds: float = Field(ge=0, le=3600)
    generation_enabled: bool
    buffer_capacity_bytes: int = Field(gt=0, le=MAX_BUFFER_CAPACITY_BYTES)

    @model_validator(mode="after")
    def validate_rate_floor(self) -> "ConfigurationRequest":
        if self.minimum_rate_bytes_per_second > self.average_rate_bytes_per_second:
            raise ValueError("minimum rate must not exceed the average rate")
        return self

    def rate_model(self) -> RateModelConfig:
        return RateModelConfig(
            **self.model_dump(exclude={"buffer_capacity_bytes"})
        ).validate()


class BufferLevelRequest(BaseModel):
    available_bytes: int = Field(ge=0, le=MAX_BUFFER_CAPACITY_BYTES)


class OutageRequest(BaseModel):
    enabled: StrictBool


@dataclass(frozen=True)
class Session:
    token: str
    csrf_token: str
    expires_at: float


class AuthenticationManager:
    """Small in-memory password/session manager for the control plane."""

    def __init__(self, password: Optional[str], *, session_hours: int = 12) -> None:
        self.enabled = password is not None
        self._password_digest = (
            hashlib.sha256(password.encode("utf-8")).digest()
            if password is not None
            else b""
        )
        self._session_seconds = session_hours * 60 * 60
        self._sessions: Dict[str, Session] = {}
        self._failures: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._anonymous = Session("", "", float("inf"))

    def login(self, password: str, client_key: str) -> Session:
        if not self.enabled:
            return self._anonymous
        now = time.time()
        with self._lock:
            failures = self._failures[client_key]
            while failures and failures[0] < now - 60:
                failures.popleft()
            if len(failures) >= 5:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many login attempts. Try again in one minute.",
                )
            supplied_digest = hashlib.sha256(password.encode("utf-8")).digest()
            if not hmac.compare_digest(supplied_digest, self._password_digest):
                failures.append(now)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password"
                )
            failures.clear()
            session = Session(
                token=secrets.token_urlsafe(32),
                csrf_token=secrets.token_urlsafe(24),
                expires_at=now + self._session_seconds,
            )
            self._sessions[session.token] = session
            self._remove_expired_locked(now)
            return session

    def get(self, token: Optional[str]) -> Session:
        if not self.enabled:
            return self._anonymous
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Login required"
            )
        now = time.time()
        with self._lock:
            session = self._sessions.get(token)
            if session is None or session.expires_at <= now:
                self._sessions.pop(token, None)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired"
                )
            return session

    def logout(self, token: Optional[str]) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(token, None)

    def _remove_expired_locked(self, now: float) -> None:
        expired = [
            token for token, item in self._sessions.items() if item.expires_at <= now
        ]
        for token in expired:
            self._sessions.pop(token, None)


def load_presets(directory: Path) -> Dict[str, dict]:
    if not directory.is_dir():
        raise ValueError(f"preset directory does not exist: {directory}")
    presets: Dict[str, dict] = {}
    for path in sorted(directory.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            preset_id = str(raw["id"])
            name = str(raw["name"])
            description = str(raw["description"])
            if not PRESET_ID_PATTERN.fullmatch(preset_id):
                raise ValueError(
                    "id must contain lowercase letters, digits, and hyphens"
                )
            if preset_id in presets:
                raise ValueError(f"duplicate id '{preset_id}'")
            config = RateModelConfig(**raw["configuration"]).validate()
            capacity = int(raw["buffer_capacity_bytes"])
            initial_fill = float(raw.get("initial_fill_percent", 0))
            if not 0 < capacity <= MAX_BUFFER_CAPACITY_BYTES:
                raise ValueError(
                    "buffer_capacity_bytes must be between 1 byte and 100 MiB"
                )
            if not 0 <= initial_fill <= 100:
                raise ValueError("initial_fill_percent must be between zero and 100")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid preset {path}: {exc}") from exc
        presets[preset_id] = {
            "id": preset_id,
            "name": name,
            "description": description,
            "configuration": asdict(config),
            "buffer_capacity_bytes": capacity,
            "initial_fill_percent": initial_fill,
        }
    if not presets:
        raise ValueError(f"no JSON presets found in {directory}")
    return presets


def create_app(
    service: MockKmsService,
    *,
    password: Optional[str],
    presets_dir: Path,
    secure_cookies: bool = False,
) -> FastAPI:
    presets = load_presets(presets_dir)
    auth = AuthenticationManager(password)
    dashboard_path = (
        Path(__file__).resolve().parent / "static" / "mock_kms_dashboard.html"
    )
    dashboard_html = dashboard_path.read_text(encoding="utf-8")
    app = FastAPI(
        title="LinQKD Mock KMS Control Plane",
        version="0.2.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'"
        )
        return response

    def current_session(request: Request) -> Session:
        return auth.get(request.cookies.get(SESSION_COOKIE))

    def csrf_session(
        request: Request, x_csrf_token: Optional[str] = Header(default=None)
    ) -> Session:
        session = current_session(request)
        csrf_required = auth.enabled
        if csrf_required and (
            x_csrf_token is None
            or not hmac.compare_digest(x_csrf_token, session.csrf_token)
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing or invalid CSRF token",
            )
        return session

    def kms_session_id(
        request: Request, identity: Session = Depends(current_session)
    ) -> str:
        x_linqkd_session = request.headers.get("X-LinQKD-Session")
        session_id = (x_linqkd_session or "standalone").strip() or "standalone"
        try:
            service.get_context(session_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return session_id

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> HTMLResponse:
        return HTMLResponse(dashboard_html)

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/api/login")
    def login(payload: LoginRequest, request: Request, response: Response) -> dict:
        client_key = request.client.host if request.client else "unknown"
        session = auth.login(payload.password, client_key)
        if auth.enabled:
            response.set_cookie(
                SESSION_COOKIE,
                session.token,
                max_age=12 * 60 * 60,
                httponly=True,
                secure=secure_cookies,
                samesite="strict",
                path="/",
            )
        return {
            "authenticated": True,
            "authentication_enabled": auth.enabled,
            "csrf_token": session.csrf_token,
        }

    @app.post("/api/logout")
    def logout(
        request: Request, response: Response, _: Session = Depends(csrf_session)
    ) -> dict:
        auth.logout(request.cookies.get(SESSION_COOKIE))
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"authenticated": False}

    @app.get("/api/session")
    def session_info(session: Session = Depends(current_session)) -> dict:
        result = {
            "authenticated": True,
            "authentication_enabled": auth.enabled,
            "authentication_mode": "standalone",
            "csrf_token": session.csrf_token,
        }
        return result

    @app.get("/api/status")
    def kms_status(
        _: Session = Depends(current_session), session_id: str = Depends(kms_session_id)
    ) -> dict:
        return service.status(session_id)

    @app.get("/api/presets")
    def preset_list(_: Session = Depends(current_session)) -> dict:
        return {"presets": list(presets.values())}

    @app.put("/api/configuration")
    def update_configuration(
        payload: ConfigurationRequest,
        _: Session = Depends(csrf_session),
        session_id: str = Depends(kms_session_id),
    ) -> dict:
        return service.apply_configuration(
            payload.rate_model(),
            capacity_bytes=payload.buffer_capacity_bytes,
            session_id=session_id,
        )

    @app.put("/api/outage")
    def update_outage(
        payload: OutageRequest,
        _: Session = Depends(csrf_session),
        session_id: str = Depends(kms_session_id),
    ) -> dict:
        service.get_context(session_id).buffer.set_outage(payload.enabled)
        service.record_sample(session_id)
        return service.status(session_id)

    @app.put("/api/buffer")
    def update_buffer(
        payload: BufferLevelRequest,
        _: Session = Depends(csrf_session),
        session_id: str = Depends(kms_session_id),
    ) -> dict:
        try:
            service.get_context(session_id).buffer.set_available_bytes(
                payload.available_bytes
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        service.record_sample(session_id)
        return service.status(session_id)

    @app.post("/api/history/clear")
    def clear_history(
        _: Session = Depends(csrf_session), session_id: str = Depends(kms_session_id)
    ) -> dict:
        return service.clear_history(session_id)

    @app.post("/api/presets/{preset_id}/apply")
    def apply_preset(
        preset_id: str,
        _: Session = Depends(csrf_session),
        session_id: str = Depends(kms_session_id),
    ) -> dict:
        preset = presets.get(preset_id)
        if preset is None:
            raise HTTPException(status_code=404, detail="Unknown preset")
        configuration = RateModelConfig(**preset["configuration"])
        capacity = preset["buffer_capacity_bytes"]
        service.apply_configuration(
            configuration, capacity_bytes=capacity, session_id=session_id
        )
        available = round(capacity * preset["initial_fill_percent"] / 100)
        service.get_context(session_id).buffer.set_available_bytes(available)
        service.record_sample(session_id)
        return service.status(session_id)

    return app
