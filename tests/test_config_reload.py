import json
import os
import tempfile
import unittest
import uuid

from lockbox.config import Config, ServiceConfig
from lockbox.generate_admin_token import generate_admin_token
from tests.utils import LocalLockboxProxyServer, LocalBlackholeServer

LOCKBOX_PROXY_SIGNING_KEY_FOR_TEST = "test_signing_key_reload"
BLACKHOLE_SERVER_PORT = 8002
LOCKBOX_PROXY_SERVER_PORT = 8003


class TestConfigReload(unittest.TestCase):
    """Test configuration reload functionality."""

    def setUp(self):
        self.blackhole_server = LocalBlackholeServer(port=BLACKHOLE_SERVER_PORT)
        self.blackhole_server.start()

        # Create a temporary config file
        self.config_fd, self.config_path = tempfile.mkstemp(suffix=".json")

    def tearDown(self):
        self.blackhole_server.stop()
        os.close(self.config_fd)
        os.unlink(self.config_path)

    def write_config(self, config: Config):
        """Write config to the temporary file."""
        with open(self.config_path, "w") as f:
            json.dump(config.model_dump(), f)

    def test_config_reload_adds_new_service(self):
        """Test that reloading config makes new services available."""
        # Start with a config that has one service
        initial_config = Config(
            services={
                "service1": ServiceConfig(
                    base_url=f"http://localhost:{BLACKHOLE_SERVER_PORT}",
                    requires_service_token=False,
                )
            }
        )
        self.write_config(initial_config)

        with LocalLockboxProxyServer(
            config_file=self.config_path,
            signing_key=LOCKBOX_PROXY_SIGNING_KEY_FOR_TEST,
            port=LOCKBOX_PROXY_SERVER_PORT,
        ) as lockbox:
            # Verify service1 works
            response = lockbox.get("/s/service1/test")
            self.assertEqual(response.status_code, 200)

            # Verify service2 doesn't exist yet
            response = lockbox.get("/s/service2/test")
            self.assertEqual(response.status_code, 404)

            # Update config to add service2
            updated_config = Config(
                services={
                    "service1": ServiceConfig(
                        base_url=f"http://localhost:{BLACKHOLE_SERVER_PORT}",
                        requires_service_token=False,
                    ),
                    "service2": ServiceConfig(
                        base_url=f"http://localhost:{BLACKHOLE_SERVER_PORT}",
                        requires_service_token=False,
                    ),
                }
            )
            self.write_config(updated_config)

            # Generate admin token and reload
            admin_token = generate_admin_token(
                duration=300, signing_key=LOCKBOX_PROXY_SIGNING_KEY_FOR_TEST
            )
            reload_response = lockbox.post(
                "/admin/reload",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            self.assertEqual(reload_response.status_code, 200)
            self.assertEqual(reload_response.json()["status"], "ok")

            # Now service2 should work
            response = lockbox.get("/s/service2/test")
            self.assertEqual(response.status_code, 200)

    def test_config_reload_requires_admin_token(self):
        """Test that reload endpoint requires valid admin token."""
        initial_config = Config(
            services={
                "test": ServiceConfig(
                    base_url=f"http://localhost:{BLACKHOLE_SERVER_PORT}",
                    requires_service_token=False,
                )
            }
        )
        self.write_config(initial_config)

        with LocalLockboxProxyServer(
            config_file=self.config_path,
            signing_key=LOCKBOX_PROXY_SIGNING_KEY_FOR_TEST,
            port=LOCKBOX_PROXY_SERVER_PORT,
        ) as lockbox:
            # Try without token
            response = lockbox.post("/admin/reload")
            self.assertEqual(response.status_code, 401)

            # Try with invalid token
            response = lockbox.post(
                "/admin/reload",
                headers={"Authorization": "Bearer invalid_token"},
            )
            self.assertEqual(response.status_code, 401)

            # Try with valid service token (not admin token)
            from lockbox.generate_service_token import generate_service_token

            service_token = generate_service_token(
                audience="test",
                service_name="test",
                duration=300,
                signing_key=LOCKBOX_PROXY_SIGNING_KEY_FOR_TEST,
            )
            response = lockbox.post(
                "/admin/reload",
                headers={"Authorization": f"Bearer {service_token}"},
            )
            self.assertEqual(
                response.status_code, 403
            )  # Forbidden - not an admin token

            # Try with valid admin token
            admin_token = generate_admin_token(
                duration=300, signing_key=LOCKBOX_PROXY_SIGNING_KEY_FOR_TEST
            )
            response = lockbox.post(
                "/admin/reload",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            self.assertEqual(response.status_code, 200)

    def test_config_reload_updates_service_config(self):
        """Test that reloading config updates existing service configuration."""
        initial_config = Config(
            services={
                "test_service": ServiceConfig(
                    base_url=f"http://localhost:{BLACKHOLE_SERVER_PORT}",
                    requires_service_token=False,
                )
            }
        )
        self.write_config(initial_config)

        with LocalLockboxProxyServer(
            config_file=self.config_path,
            signing_key=LOCKBOX_PROXY_SIGNING_KEY_FOR_TEST,
            port=LOCKBOX_PROXY_SERVER_PORT,
        ) as lockbox:
            # Initially no token required
            response = lockbox.get("/s/test_service/test")
            self.assertEqual(response.status_code, 200)

            # Update config to require service token
            updated_config = Config(
                services={
                    "test_service": ServiceConfig(
                        base_url=f"http://localhost:{BLACKHOLE_SERVER_PORT}",
                        requires_service_token=True,
                    )
                }
            )
            self.write_config(updated_config)

            # Reload config
            admin_token = generate_admin_token(
                duration=300, signing_key=LOCKBOX_PROXY_SIGNING_KEY_FOR_TEST
            )
            reload_response = lockbox.post(
                "/admin/reload",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            self.assertEqual(reload_response.status_code, 200)

            # Now requests without token should fail
            response = lockbox.get("/s/test_service/test")
            self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
