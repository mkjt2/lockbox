import unittest

from lockbox.config import Config, Service
from lockbox.generate_service_token import generate_service_token
from tests.utils import LocalLockboxProxyServer, LocalBlackholeServer

LOCKBOX_PROXY_SIGNING_KEY_FOR_TEST = "abc"
BLACKHOLE_SERVER_PORT = 8001
LOCKBOX_PROXY_SERVER_PORT = 8000


class TestEverything(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.blackhole_server = LocalBlackholeServer(port=BLACKHOLE_SERVER_PORT)
        self.blackhole_server.start()

    def tearDown(self):
        self.blackhole_server.stop()

    def get_lockbox_proxy_server(self, config: Config, signing_key: str | None):
        return LocalLockboxProxyServer(config=config, signing_key=signing_key)

    def test_local_lockbox_proxy_server(self):
        with LocalLockboxProxyServer(config=Config(services={}), signing_key=None):
            pass

    def test_local_blackhole_server(self):
        with LocalBlackholeServer():
            pass

    def test_identical_response(self):
        lockbox_config = Config(
            services={
                "blackhole": Service(
                    base_url=f"http://localhost:{BLACKHOLE_SERVER_PORT}",
                    # TODO also test False
                    # TODO test for credentials (one for each type at least)
                    # TODO dedupe "blackhole" string
                    requires_service_token=True,
                )
            }
        )
        service_token = generate_service_token(
            service_name="blackhole",
            duration=600,
            signing_key=LOCKBOX_PROXY_SIGNING_KEY_FOR_TEST,
            audience="test_everything",
        )
        test_cases = [
            {
                "service_path": "some_path/whatever",
                "params": {"a": 1, "b": "2"},
                "data": {"c": 3, "d": "4"},
                "method": "GET",
                # TODO test extra headers (meant for dest service)
                "expected_status_code": 200,
            },
            {
                "service_path": "some_path/whatever",
                "params": {"a": 1, "b": "2"},
                "data": {"c": 3, "d": "4"},
                "method": "PUT",
                "expected_status_code": 200,
            },
            {
                "service_path": "some_path/whatever",
                "params": {"a": 1, "b": "2"},
                "data": {"c": 3, "d": "4"},
                "method": "POST",
                "expected_status_code": 200,
            },
            {
                "service_path": "some_path/whatever",
                "params": {"a": 1, "b": "2"},
                "data": b"somebytes",
                "method": "POST",
                "expected_status_code": 200,
            },
            {
                "service_path": "",
                "params": {"a": 1, "b": "2"},
                "data": {"c": 3, "d": "4"},
                "method": "DELETE",
                "expected_status_code": 200,
            },
        ]

        headers = {"Authorization": f"Bearer {service_token}"}

        with self.get_lockbox_proxy_server(
            lockbox_config, LOCKBOX_PROXY_SIGNING_KEY_FOR_TEST
        ) as lockbox_proxy_server:
            for test_case in test_cases:

                service_path = test_case["service_path"]
                params = test_case["params"]
                method = test_case["method"]
                data = test_case["data"]

                try:
                    lockbox_request_fn = getattr(lockbox_proxy_server, method.lower())
                    blackhole_request_fn = getattr(
                        self.blackhole_server, method.lower()
                    )
                except AttributeError:
                    raise NotImplementedError(f"Unsupported method: {method}")

                lockbox_response = lockbox_request_fn(
                    f"/s/blackhole/{service_path}",
                    params=params,
                    data=data,
                    headers=headers,
                )
                blackhole_response = blackhole_request_fn(
                    f"/{service_path}", params=params, data=data
                )

                self.assertEqual(
                    lockbox_response.status_code,
                    test_case["expected_status_code"],
                    lockbox_response.text,
                )

                self.assertEqual(
                    blackhole_response.status_code, test_case["expected_status_code"]
                )

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
