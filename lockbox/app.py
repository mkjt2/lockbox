import dataclasses
import logging
import os
import sys
import time
import uuid
from typing import Any

import jwt
from flask import Flask, request, make_response
import requests
from requests.auth import HTTPBasicAuth

from lockbox import JWT_ISSUER_LOCKBOX
from lockbox.audit_log import get_audit_log_provider, Event, AuditLogProvider
from lockbox.config import (
    load_config,
    Config,
    BasicAuthCredentialConfig,
    BearerTokenCredentialConfig,
    HeadersCredentialConfig,
)
from lockbox.utils import _safe_decode_text_data

app = Flask(__name__)

# Setup logging ASAP
# Credit: https://trstringer.com/logging-flask-gunicorn-the-manageable-way/
if __name__ != "__main__":
    gunicorn_logger = logging.getLogger("gunicorn.error")
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)


class ConfigManager:
    """Lock-free configuration manager with hot-reload support.

    Uses atomic reference assignments (guaranteed by Python's GIL) to avoid locks.
    There's a tiny window where config and audit_log_provider might be inconsistent
    during reload, but this has no practical impact - at worst a few events get
    logged to the old audit directory.
    """

    def __init__(self, config_path: str):
        self._config_path = config_path
        self._config: Config | None = None
        self._audit_log_provider: AuditLogProvider | None = None
        self._load_config()

    def _load_config(self) -> None:
        """Internal method to load config from disk."""
        new_config = load_config(self._config_path)

        # Update audit log provider based on new config
        if new_config.audit_log:
            new_audit_log_provider = get_audit_log_provider(new_config.audit_log)
        else:
            new_audit_log_provider = None

        # Atomic assignments - GIL ensures these are thread-safe
        self._config = new_config
        self._audit_log_provider = new_audit_log_provider

    def reload(self) -> None:
        """Reload configuration from disk."""
        self._load_config()
        app.logger.info(f"Configuration reloaded from {self._config_path}")

    def get_config(self) -> Config:
        """Get current config."""
        if self._config is None:
            raise RuntimeError("Configuration not initialized")
        return self._config

    def get_audit_log_provider(self) -> AuditLogProvider | None:
        """Get current audit log provider."""
        return self._audit_log_provider


try:
    config_manager = ConfigManager(os.environ["LOCKBOX_CONFIG_PATH"])
except KeyError as ke:
    app.logger.error(f"Please set LOCKBOX_CONFIG_PATH env var")
    sys.exit(1)
except Exception as e:
    app.logger.error(f"Error loading config: {e}")
    sys.exit(1)


@dataclasses.dataclass
class ValidateServiceTokenResult:
    error_message: str | None = None
    error_status_code: int | None = None
    service_token_payload: dict[str, Any] | None = None


def validate_service_token(
    audiences: list[str] | None, service_name: str, service_token: str, signing_key: str
) -> ValidateServiceTokenResult:
    service_token_payload = None
    try:
        service_token_payload = jwt.decode(
            service_token,
            signing_key,
            algorithms=["HS256"],
            options={"verify_signature": False},
        )
        if service_token_payload["iss"] != JWT_ISSUER_LOCKBOX:
            return ValidateServiceTokenResult(
                error_message="Invalid service_name token (bad issuer)",
                error_status_code=401,
                service_token_payload=service_token_payload,
            )
        if service_token_payload["exp"] < time.time():
            return ValidateServiceTokenResult(
                error_message="Invalid service_name token (expired)",
                error_status_code=401,
                service_token_payload=service_token_payload,
            )
        if service_token_payload["service_name"] != service_name:
            return ValidateServiceTokenResult(
                error_message="Invalid service_name token (wrong service_name)",
                error_status_code=401,
                service_token_payload=service_token_payload,
            )
    except Exception as e:
        return ValidateServiceTokenResult(
            error_message="Invalid service_name token",
            error_status_code=401,
            service_token_payload=service_token_payload,
        )
    try:
        allowed_audiences = []
        if audiences is not None:
            allowed_audiences.extend(audiences)
        else:
            allowed_audiences.append(service_token_payload["aud"])
        # verify signature this time
        service_token_payload = jwt.decode(
            service_token, signing_key, algorithms=["HS256"], audience=allowed_audiences
        )
        return ValidateServiceTokenResult(service_token_payload=service_token_payload)
    except Exception as e:
        app.logger.debug(f"JWT validation failed: {e}")
        return ValidateServiceTokenResult(
            error_message="Invalid service_name token (bad audience)",
            error_status_code=401,
            service_token_payload=service_token_payload,
        )


_signing_key: str | None = None


def get_signing_key() -> str:
    global _signing_key
    if _signing_key is None:
        # Check the service_name token
        signing_key_file = os.getenv("LOCKBOX_SIGNING_KEY_FILE")
        if signing_key_file is None:
            raise Exception("Missing LOCKBOX_SIGNING_KEY_FILE environment variable")
        with open(signing_key_file) as f:
            _signing_key = f.read()
    return _signing_key


def _log_request() -> None:
    app.logger.debug(f"Request args = {request.args}")
    for k, v in request.headers.items():
        app.logger.debug(f"Request header: {k} => {v}")


def _check_service_token_auth(
    service_config: "ServiceConfig", service_name: str
) -> ValidateServiceTokenResult:
    """Check if the incoming request has a valid service token.

    Args:
        service_config: Service configuration
        service_name: Name of the service being accessed

    Returns:
        ValidateServiceTokenResult with error or payload
    """
    if "Authorization" not in request.headers:
        return ValidateServiceTokenResult(
            error_message="Missing Authorization header", error_status_code=401
        )

    auth_header = request.headers["Authorization"]
    if not auth_header.startswith("Bearer "):
        return ValidateServiceTokenResult(
            error_message="Invalid Authorization header", error_status_code=401
        )

    service_token = auth_header[len("Bearer ") :]

    try:
        signing_key = get_signing_key()
    except Exception:
        return ValidateServiceTokenResult(
            error_message="Could not determine Lockbox signing key",
            error_status_code=500,
        )

    return validate_service_token(
        audiences=service_config.valid_audiences,
        service_name=service_name,
        service_token=service_token,
        signing_key=signing_key,
    )


@dataclasses.dataclass
class PreparedServiceRequest:
    """Prepared request ready to be sent to the upstream service."""

    headers: dict[str, str]
    auth: HTTPBasicAuth | None
    timeout: tuple[float | None, float | None] | None
    error: tuple[str, int] | None = (
        None  # (error_message, status_code) if preparation failed
    )


def _prepare_service_request(
    service_config: "ServiceConfig",
) -> PreparedServiceRequest:
    """Prepare headers, auth, and timeout for the upstream service request.

    Args:
        service_config: Service configuration

    Returns:
        PreparedServiceRequest with headers, auth, timeout, or error
    """
    service_headers = {}
    requests_auth = None

    # Build timeout tuple from config, or None if both are None
    request_timeout = None
    if (
        service_config.connect_timeout is not None
        or service_config.read_timeout is not None
    ):
        request_timeout = (service_config.connect_timeout, service_config.read_timeout)

    # Prepare credentials
    if service_config.credential:
        if isinstance(service_config.credential, BasicAuthCredentialConfig):
            requests_auth = HTTPBasicAuth(
                service_config.credential.username, service_config.credential.password
            )
        elif isinstance(service_config.credential, BearerTokenCredentialConfig):
            service_headers["Authorization"] = (
                f"Bearer {service_config.credential.token}"
            )
        elif isinstance(service_config.credential, HeadersCredentialConfig):
            service_headers.update(service_config.credential.headers)
        else:
            return PreparedServiceRequest(
                headers={},
                auth=None,
                timeout=None,
                error=(
                    f"Invalid credential type: {service_config.credential.type}",
                    500,
                ),
            )

    return PreparedServiceRequest(
        headers=service_headers,
        auth=requests_auth,
        timeout=request_timeout,
    )


def _build_lockbox_response(upstream_response: requests.Response):
    """Build Flask response from upstream service response.

    Args:
        upstream_response: Response from the upstream service

    Returns:
        Flask Response object
    """
    # Use response.content (bytes) to preserve binary data
    lockbox_response = make_response(upstream_response.content)

    # Filter out hop-by-hop headers that shouldn't be forwarded
    HOP_BY_HOP_HEADERS = {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
    for k, v in upstream_response.headers.items():
        if k.lower() not in HOP_BY_HOP_HEADERS:
            lockbox_response.headers[k] = v

    lockbox_response.status_code = upstream_response.status_code
    return lockbox_response


@app.route("/healthz")
def healthz():
    return "OK"


@app.route("/admin/reload", methods=["POST"])
def admin_reload():
    """Reload configuration from disk without restarting the server.

    Requires authentication via the same signing key used for service tokens.
    Send a POST request with an Authorization header containing a valid admin token.

    Admin tokens can be generated with:
        python -c "import jwt, time; print(jwt.encode({'iss': 'lockbox', 'exp': int(time.time() + 3600), 'admin': True}, open('signing_key.txt').read(), algorithm='HS256'))"
    """
    # Check authorization
    if "Authorization" not in request.headers:
        return "Missing Authorization header", 401

    auth_header = request.headers["Authorization"]
    if not auth_header.startswith("Bearer "):
        return "Invalid Authorization header", 401

    token = auth_header[len("Bearer ") :]

    try:
        signing_key = get_signing_key()
    except Exception:
        app.logger.error("Could not determine Lockbox signing key for admin endpoint")
        return "Server configuration error", 500

    try:
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["HS256"],
            options={"verify_signature": True, "verify_aud": False},
        )
    except Exception as e:
        app.logger.debug(f"Admin token validation failed: {e}")
        return "Invalid token", 401

    # Verify issuer and admin claim
    if payload.get("iss") != JWT_ISSUER_LOCKBOX:
        return "Invalid token (bad issuer)", 401

    if payload.get("exp", 0) < time.time():
        return "Invalid token (expired)", 401

    if not payload.get("admin"):
        return "Invalid token (not an admin token)", 403

    # Perform reload
    try:
        config_manager.reload()
        return {"status": "ok", "message": "Configuration reloaded successfully"}, 200
    except Exception as e:
        app.logger.error(f"Failed to reload configuration: {e}")
        return {"status": "error", "message": str(e)}, 500


@app.route("/s/<service_name>/", methods=["GET", "POST", "PUT", "DELETE"])
@app.route("/s/<service_name>/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE"])
def service(service_name: str, subpath: str = ""):
    # TODO check: can subpath be empty or None?

    request_id = str(uuid.uuid4())

    def _make_event(event_name: str, payload):
        return Event(
            # i.e. request_to_lockbox, lockbox_auth_failure, request_to_service, response_from_service, response_from_lockbox, lockbox_internal_error
            ts=time.time(),
            event_name=event_name,
            service_name=service_name,
            request_id=request_id,
            payload=payload,
        )

    _log_request()

    # Get current config and audit log provider
    config = config_manager.get_config()
    audit_log_provider = config_manager.get_audit_log_provider()

    if audit_log_provider:
        # Decode request data and check if it's valid UTF-8 text
        decoded_data, is_text = _safe_decode_text_data(request.data)
        if not is_text:
            app.logger.warning(
                f"Skipping audit log for request with binary data - Service: {service_name}, Request ID: {request_id}"
            )
        else:
            audit_log_provider.log_service_event(
                event=_make_event(
                    event_name="request_to_lockbox",
                    payload={
                        "request": {
                            "method": request.method,
                            "path": request.path,
                            "args": request.args,
                            "headers": dict(request.headers),
                            "data": decoded_data,
                            "form": request.form,
                        }
                    },
                )
            )

    service_config = config.get_service_config(service_name)
    if service_config is None:
        return f"Invalid service_name {service_name}", 404

    # Check service token authorization if required
    if service_config.requires_service_token:
        validation_result = _check_service_token_auth(service_config, service_name)

        if validation_result.error_status_code is not None:
            if audit_log_provider:
                event = _make_event(
                    event_name="lockbox_auth_failure",
                    payload={
                        "error": validation_result.error_message,
                        "service_token_payload": validation_result.service_token_payload,
                    },
                )
                audit_log_provider.log_service_event(event)
            return str(validation_result.error_message), int(
                validation_result.error_status_code
            )

        if audit_log_provider:
            event = _make_event(
                event_name="lockbox_auth_success",
                payload={
                    "service_token_payload": validation_result.service_token_payload
                },
            )
            audit_log_provider.log_service_event(event)

    # Prepare request (headers, auth, timeout)
    prepared_request = _prepare_service_request(service_config)
    if prepared_request.error:
        error_message, error_status = prepared_request.error
        event = _make_event(
            event_name="lockbox_internal_error",
            payload={"error": error_message},
        )
        if audit_log_provider:
            audit_log_provider.log_service_event(event)
        return error_message, error_status

    # Build service request URL
    service_request_url = f"{service_config.base_url}/{subpath}"

    # Validate HTTP method
    if request.method not in ("GET", "POST", "PUT", "DELETE"):
        event = _make_event(
            event_name="lockbox_internal_error",
            payload={"error": f"Unsupported method: {request.method}"},
        )
        if audit_log_provider:
            audit_log_provider.log_service_event(event)
        return f"Unsupported method: {request.method}", 405

    # Make request to upstream service
    response = requests.request(
        method=request.method,
        url=service_request_url,
        headers=prepared_request.headers,
        params=request.args,
        data=request.form or request.data,
        auth=prepared_request.auth,
        timeout=prepared_request.timeout,
        allow_redirects=service_config.allow_redirects,
    )

    # Build response to send back to client
    lockbox_response = _build_lockbox_response(response)
    if audit_log_provider:
        audit_log_provider.log_service_event(
            event=_make_event(
                event_name="response_from_service",
                payload={
                    "response": {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "data": response.text,
                    }
                },
            )
        )
    return lockbox_response
