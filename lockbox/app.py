import logging
import os
import time

import jwt
from flask import Flask, request, make_response
import requests
from requests.auth import HTTPBasicAuth

from lockbox import JWT_ISSUER_LOCKBOX
from lockbox.config import (
    load_config,
    BasicAuthCredential,
    BearerTokenCredential,
    HeadersCredential,
)

app = Flask(__name__)
app.logger.level = logging.DEBUG

config = load_config(os.environ["LOCKBOX_CONFIG_PATH"])


def validate_service_token(
    audiences: list[str] | None, service_name: str, service_token: str, signing_key: str
) -> tuple[str, int] | None:
    try:
        service_token_payload = jwt.decode(
            service_token,
            signing_key,
            algorithms=["HS256"],
            options={"verify_signature": False},
        )
        if service_token_payload["iss"] != JWT_ISSUER_LOCKBOX:
            return "Invalid service_name token (bad issuer)", 401
        if service_token_payload["exp"] < time.time():
            return "Invalid service_name token (expired)", 401
        if service_token_payload["service_name"] != service_name:
            return "Invalid service_name token (wrong service_name)", 401
    except Exception as e:
        return "Invalid service_name token", 401
    try:
        allowed_audiences = []
        if audiences is not None:
            allowed_audiences.extend(audiences)
        else:
            allowed_audiences.append(service_token_payload["aud"])
        jwt.decode(
            service_token, signing_key, algorithms=["HS256"], audience=allowed_audiences
        )
    except Exception as e:
        return "Invalid service_name token (bad audience)", 401


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
    _log_request()

    service_config = config.get_service_config(service_name)
    if service_config is None:
        return f"Invalid service_name {service_name}", 404

    if service_config.requires_service_token:
        if "Authorization" not in request.headers:
            return "Missing Authorization header", 401
        auth_header = request.headers["Authorization"]
        if not auth_header.startswith("Bearer "):
            return "Invalid Authorization header", 401
        service_token = auth_header[len("Bearer ") :]

        try:
            signing_key = get_signing_key()
        except Exception:
            return "Could not determine Lockbox signing key", 500

        failure_response = validate_service_token(
            audiences=service_config.valid_audiences,
            service_name=service_name,
            service_token=service_token,
            signing_key=signing_key,
        )
        if failure_response:
            return failure_response

    service_request_url = f"{service_config.base_url}/{subpath}"

    service_headers = {}

    requests_auth = None
    if service_config.credential:
        if isinstance(service_config.credential, BasicAuthCredential):
            requests_auth = HTTPBasicAuth(
                service_config.credential.username, service_config.credential.password
            )
        elif isinstance(service_config.credential, BearerTokenCredential):
            service_headers[
                "Authorization"
            ] = f"Bearer {service_config.credential.token}"
        elif isinstance(service_config.credential, HeadersCredential):
            service_headers.update(service_config.credential.headers)
        else:
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
        return f"Unsupported method: {request.method}", 405

    lockbox_response = make_response(response.text)
    for k, v in response.headers.items():
        lockbox_response.headers[k] = v
    lockbox_response.status_code = response.status_code
    return lockbox_response
