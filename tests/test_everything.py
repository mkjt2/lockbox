import base64
import dataclasses
import os
import shutil
import unittest
import uuid
from typing import Any

from lockbox.config import (
    Config,
    ServiceConfig,
    CredentialType,
    BasicAuthCredentialConfig,
    BearerTokenCredentialConfig,
    HeadersCredentialConfig,
    LocalDirAuditLogConfig,
)
from lockbox.generate_service_token import generate_service_token
from tests.utils import LocalLockboxProxyServer, LocalBlackholeServer

LOCKBOX_PROXY_SIGNING_KEY_FOR_TEST = "abc"
BLACKHOLE_SERVER_PORT = 8001
LOCKBOX_PROXY_SERVER_PORT = 8000


@dataclasses.dataclass
class TestCase:
    service_name: str
    service_path: str
    method: str
    expected_lockbox_status_code: int
    expected_blackhole_status_code: int
    params: dict[str, Any] | None
    data: dict[str, Any] | bytes | str | None
    lockbox_auth_headers: dict[str, str] | None = None
    blackhole_auth_headers: dict[str, str] | None = None


def _get_blackhole_service_config(
    auth_type: CredentialType | None,
    requires_service_token: bool,
    valid_audiences: list[str] | None,
) -> tuple[str, ServiceConfig]:
    if auth_type is None:
        base_service_name = "blackhole_no_auth"
        credential = None
    elif auth_type == CredentialType.BASIC:
        base_service_name = "blackhole_with_basic_auth"
        credential = BasicAuthCredentialConfig(username="user", password="pass")
    elif auth_type == CredentialType.BEARER:
        base_service_name = "blackhole_with_bearer_auth"
        credential = BearerTokenCredentialConfig(token="token")
    elif auth_type == CredentialType.HEADERS:
        base_service_name = "blackhole_with_headers_auth"
        credential = HeadersCredentialConfig(headers={"X-Blackhole-API-Key": "api_key"})
    else:
        raise NotImplementedError(f"Unsupported auth type: {auth_type}")
    if requires_service_token:
        service_name = f"{base_service_name}_requires_token"
    else:
        service_name = base_service_name
    if valid_audiences is not None:
        service_name = f"{service_name}_with_valid_audiences_{len(valid_audiences)}"
    return service_name, ServiceConfig(
        base_url=f"http://localhost:{BLACKHOLE_SERVER_PORT}",
        credential=credential,
        requires_service_token=requires_service_token,
        valid_audiences=valid_audiences,
    )


AUDIT_LOGS_DIR = f"/tmp/lockbox_audit_logs-{str(uuid.uuid4())}"


class TestEverything(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.blackhole_server = LocalBlackholeServer(port=BLACKHOLE_SERVER_PORT)
        self.blackhole_server.start()

    def tearDown(self):
        self.blackhole_server.stop()

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(AUDIT_LOGS_DIR):
            shutil.rmtree(AUDIT_LOGS_DIR)

    def get_lockbox_proxy_server(self, config: Config, signing_key: str | None):
        return LocalLockboxProxyServer(config=config, signing_key=signing_key)

    def test_local_lockbox_proxy_server(self):
        with LocalLockboxProxyServer(config=Config(services={}), signing_key=None):
            pass

    def test_local_blackhole_server(self):
        with LocalBlackholeServer():
            pass

    def test_identical_response(self):
        lockbox_config_services = {}
        for auth_type in list(CredentialType) + [None]:
            for requires_service_token in (True, False):
                if requires_service_token:
                    for valid_audiences in [None, [], ["test_everything"]]:
                        service_name, service = _get_blackhole_service_config(
                            auth_type,
                            requires_service_token,
                            valid_audiences=valid_audiences,
                        )
                        if service_name in lockbox_config_services:
                            raise ValueError(f"Duplicate service name: {service_name}")
                        lockbox_config_services[service_name] = service
                else:
                    service_name, service = _get_blackhole_service_config(
                        auth_type, requires_service_token, valid_audiences=None
                    )
                    if service_name in lockbox_config_services:
                        raise ValueError(f"Duplicate service name: {service_name}")
                    lockbox_config_services[service_name] = service

        lockbox_config = Config(
            services=lockbox_config_services,
            audit_log=LocalDirAuditLogConfig(root_dir=AUDIT_LOGS_DIR),
        )

        test_cases = []
        for service_name, service in lockbox_config_services.items():
            if service.credential is None:
                blackhole_auth_headers = None
            elif service.credential.type == CredentialType.BASIC:
                blackhole_auth_headers = {
                    "Authorization": f"Basic {base64.b64encode(b'user:pass').decode()}"
                }
            elif service.credential.type == CredentialType.BEARER:
                blackhole_auth_headers = {"Authorization": "Bearer token"}
            elif service.credential.type == CredentialType.HEADERS:
                blackhole_auth_headers = {"X-Blackhole-API-Key": "api_key"}
            else:
                raise NotImplementedError(
                    "Unsupported auth type encountered during test case generation"
                )

            expected_lockbox_status_code = 200
            expected_blackhole_status_code = 200
            if service.requires_service_token:

                if service.valid_audiences == []:
                    expected_lockbox_status_code = 401

                _service_token = generate_service_token(
                    service_name=service_name,
                    duration=300,
                    signing_key=LOCKBOX_PROXY_SIGNING_KEY_FOR_TEST,
                    audience="test_everything",
                )
                lockbox_auth_headers = {"Authorization": f"Bearer {_service_token}"}
            else:
                lockbox_auth_headers = None

            test_cases.extend(
                [
                    TestCase(
                        service_name=service_name,
                        service_path="some_path/whatever",
                        params={"a": 1, "b": "2"},
                        data={"c": 3, "d": "4"},
                        method="GET",
                        expected_lockbox_status_code=expected_lockbox_status_code,
                        expected_blackhole_status_code=expected_blackhole_status_code,
                        lockbox_auth_headers=lockbox_auth_headers,
                        blackhole_auth_headers=blackhole_auth_headers,
                    ),
                    TestCase(
                        service_name=service_name,
                        service_path="some_path/whatever",
                        params={"a": 1, "b": "2"},
                        data={"c": 3, "d": "4"},
                        method="PUT",
                        expected_lockbox_status_code=expected_lockbox_status_code,
                        expected_blackhole_status_code=expected_blackhole_status_code,
                        lockbox_auth_headers=lockbox_auth_headers,
                        blackhole_auth_headers=blackhole_auth_headers,
                    ),
                    TestCase(
                        service_name=service_name,
                        service_path="some_path/whatever",
                        params={"a": 1, "b": "2"},
                        data={"c": 3, "d": "4"},
                        method="POST",
                        expected_lockbox_status_code=expected_lockbox_status_code,
                        expected_blackhole_status_code=expected_blackhole_status_code,
                        lockbox_auth_headers=lockbox_auth_headers,
                        blackhole_auth_headers=blackhole_auth_headers,
                    ),
                    TestCase(
                        service_name=service_name,
                        service_path="some_path/whatever",
                        params={"a": 1, "b": "2"},
                        data=b"somebytes",
                        method="POST",
                        expected_lockbox_status_code=expected_lockbox_status_code,
                        expected_blackhole_status_code=expected_blackhole_status_code,
                        lockbox_auth_headers=lockbox_auth_headers,
                        blackhole_auth_headers=blackhole_auth_headers,
                    ),
                    TestCase(
                        service_name=service_name,
                        service_path="",
                        params={"a": 1, "b": "2"},
                        data={"c": 3, "d": "4"},
                        method="DELETE",
                        expected_lockbox_status_code=expected_lockbox_status_code,
                        expected_blackhole_status_code=expected_blackhole_status_code,
                        lockbox_auth_headers=lockbox_auth_headers,
                        blackhole_auth_headers=blackhole_auth_headers,
                    ),
                ]
            )

        with self.get_lockbox_proxy_server(
            lockbox_config, LOCKBOX_PROXY_SIGNING_KEY_FOR_TEST
        ) as lockbox_proxy_server:
            for test_case in test_cases:
                service_name = test_case.service_name
                service_path = test_case.service_path
                params = test_case.params
                method = test_case.method
                data = test_case.data
                lockbox_auth_headers = test_case.lockbox_auth_headers
                blackhole_auth_headers = test_case.blackhole_auth_headers

                try:
                    lockbox_request_fn = getattr(lockbox_proxy_server, method.lower())
                    blackhole_request_fn = getattr(
                        self.blackhole_server, method.lower()
                    )
                except AttributeError:
                    raise NotImplementedError(f"Unsupported method: {method}")

                lockbox_response = lockbox_request_fn(
                    f"/s/{service_name}/{service_path}",
                    params=params,
                    data=data,
                    headers=lockbox_auth_headers,
                )
                blackhole_response = blackhole_request_fn(
                    f"/{service_path}",
                    params=params,
                    data=data,
                    headers=blackhole_auth_headers,
                )

                self.assertEqual(
                    lockbox_response.status_code,
                    test_case.expected_lockbox_status_code,
                    lockbox_response.text,
                )

                self.assertEqual(
                    blackhole_response.status_code,
                    test_case.expected_blackhole_status_code,
                )

                # Only check response body and headers if both responses are 200
                if (
                    blackhole_response.status_code == 200
                    and lockbox_response.status_code == 200
                ):
                    self.assertEqual(
                        lockbox_response.json(),
                        blackhole_response.json(),
                    )

                    self.assertEqual(
                        dict(lockbox_response.headers),
                        dict(blackhole_response.headers),
                    )


if __name__ == "__main__":
    unittest.main()
