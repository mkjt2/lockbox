import dataclasses
import logging
import os
import time
import uuid
from typing import Any

import jwt
from flask import Flask, request, make_response
import requests
from requests.auth import HTTPBasicAuth

from lockbox import JWT_ISSUER_LOCKBOX
from lockbox.audit_log import get_audit_log_provider, Event
from lockbox.config import (
    load_config,
    BasicAuthCredentialConfig,
    BearerTokenCredentialConfig,
    HeadersCredentialConfig,
)

app = Flask(__name__)

config = load_config(os.environ["LOCKBOX_CONFIG_PATH"])
if config.audit_log:
    audit_log_provider = get_audit_log_provider(config.audit_log)
else:
    audit_log_provider = None


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
        print(e)
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


@app.route("/healthz")
def healthz():
    return "OK"


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
    if audit_log_provider:
        audit_log_provider.log_service_event(
            event=_make_event(
                event_name="request_to_lockbox",
                payload={
                    "request": {
                        "method": request.method,
                        "path": request.path,
                        "args": request.args,
                        "headers": dict(request.headers),
                        "data": request.data.decode("utf-8"),
                        "form": request.form,
                    }
                },
            )
        )

    service_config = config.get_service_config(service_name)
    if service_config is None:
        return f"Invalid service_name {service_name}", 404

    if service_config.requires_service_token:

        def _check_service_token() -> ValidateServiceTokenResult:
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

        validation_result = _check_service_token()
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
                assert validation_result.error_message is not None
                assert validation_result.error_status_code is not None
            return str(validation_result.error_message), int(
                validation_result.error_status_code
            )
        else:
            if audit_log_provider:
                event = _make_event(
                    event_name="lockbox_auth_success",
                    payload={
                        "service_token_payload": validation_result.service_token_payload
                    },
                )
                audit_log_provider.log_service_event(event)

    service_request_url = f"{service_config.base_url}/{subpath}"

    service_headers = {}

    requests_auth = None
    if service_config.credential:
        if isinstance(service_config.credential, BasicAuthCredentialConfig):
            requests_auth = HTTPBasicAuth(
                service_config.credential.username, service_config.credential.password
            )
        elif isinstance(service_config.credential, BearerTokenCredentialConfig):
            service_headers[
                "Authorization"
            ] = f"Bearer {service_config.credential.token}"
        elif isinstance(service_config.credential, HeadersCredentialConfig):
            service_headers.update(service_config.credential.headers)
        else:
            event = _make_event(
                event_name="lockbox_internal_error",
                payload={
                    "error": f"Invalid credential type: {service_config.credential.type}",
                },
            )
            if audit_log_provider:
                audit_log_provider.log_service_event(event)
            return f"Invalid credential type: {service_config.credential.type}", 500
    if request.method == "GET":
        response = requests.get(
            service_request_url,
            headers=service_headers,
            params=request.args,
            data=request.form or request.data,
            auth=requests_auth,
        )
    elif request.method == "PUT":
        response = requests.put(
            service_request_url,
            headers=service_headers,
            params=request.args,
            data=request.form or request.data,
            auth=requests_auth,
        )
    elif request.method == "POST":
        response = requests.post(
            service_request_url,
            headers=service_headers,
            params=request.args,
            data=request.form or request.data,
            auth=requests_auth,
        )
    elif request.method == "DELETE":
        response = requests.delete(
            service_request_url,
            headers=service_headers,
            params=request.args,
            data=request.form or request.data,
            auth=requests_auth,
        )
    else:
        event = _make_event(
            event_name="lockbox_internal_error",
            payload={
                "error": f"Unsupported method: {request.method}",
            },
        )
        if audit_log_provider:
            audit_log_provider.log_service_event(event)
        return f"Unsupported method: {request.method}", 405

    lockbox_response = make_response(response.text)
    for k, v in response.headers.items():
        lockbox_response.headers[k] = v
    lockbox_response.status_code = response.status_code
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


# Credit: https://trstringer.com/logging-flask-gunicorn-the-manageable-way/
if __name__ != "__main__":
    gunicorn_logger = logging.getLogger("gunicorn.error")
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
