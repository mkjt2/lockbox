import os.path
import signal
import subprocess
import tempfile
import time
from contextlib import AbstractContextManager
from typing import Callable

import requests

from lockbox.config import Config


class LocalServer(AbstractContextManager):
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def is_healthy(self) -> bool: ...


class LocalGunicornServer(LocalServer):
    def __init__(self, port: int = 8000):
        super().__init__()
        self._port: int = port
        self._proc: subprocess.Popen | None = None

    def is_healthy(self) -> bool:
        try:
            response = requests.get(f"http://localhost:{self._port}/healthz")
            return response.status_code == 200
        except Exception:
            return False

    def _start_gunicorn(
        self, app_path: str, env: dict[str, str] = os.environ.copy()
    ) -> None:
        self._proc = subprocess.Popen(
            ["gunicorn", app_path, "--preload", "-b", f"localhost:{self._port}"],
            env=env,
        )
        wait_for_condition(self.is_healthy)

    def _stop_gunicorn(self) -> None:
        assert self._proc
        self._proc.send_signal(signal.SIGINT)
        self._proc.wait(timeout=5)
        self._proc = None

    def get(self, path: str, *args, **kwargs):
        return requests.get(f"http://localhost:{self._port}{path}", *args, **kwargs)

    def post(self, path: str, *args, **kwargs):
        return requests.post(f"http://localhost:{self._port}{path}", *args, **kwargs)

    def put(self, path: str, *args, **kwargs):
        return requests.put(f"http://localhost:{self._port}{path}", *args, **kwargs)

    def delete(self, path: str, *args, **kwargs):
        return requests.delete(f"http://localhost:{self._port}{path}", *args, **kwargs)

    def patch(self, path: str, *args, **kwargs):
        return requests.patch(f"http://localhost:{self._port}{path}", *args, **kwargs)

    def head(self, path: str, *args, **kwargs):
        return requests.head(f"http://localhost:{self._port}{path}", *args, **kwargs)


class LocalBlackholeServer(LocalGunicornServer):
    def start(self) -> None:
        self._start_gunicorn("tests.blackhole_app:app")

    def stop(self) -> None:
        self._stop_gunicorn()


class LocalLockboxProxyServer(LocalGunicornServer):
    def __init__(
        self,
        config: Config | None = None,
        signing_key: str | None = None,
        port: int = 8000,
        config_file: str | None = None,
    ):
        """Initialize LocalLockboxProxyServer.

        Args:
            config: Config object to use (creates temp file). Mutually exclusive with config_file.
            signing_key: Signing key string (creates temp file if provided)
            port: Port to run server on
            config_file: Path to existing config file to use. Mutually exclusive with config.
        """
        super().__init__(port)
        if config is not None and config_file is not None:
            raise ValueError("Cannot specify both config and config_file")
        if config is None and config_file is None:
            raise ValueError("Must specify either config or config_file")

        self._lockbox_config: Config | None = config
        self._lockbox_config_file_external: str | None = config_file
        self._lockbox_config_file_temp: str | None = None
        self._lockbox_signing_key: str | None = signing_key
        self._lockbox_signing_key_file: str | None = None

    def start(self) -> None:
        env = os.environ.copy()

        # Set up config file
        if self._lockbox_config_file_external:
            # Use external config file
            env["LOCKBOX_CONFIG_PATH"] = self._lockbox_config_file_external
        else:
            # Create temp config file from Config object
            self._lockbox_config_file_temp = tempfile.mktemp()
            with open(self._lockbox_config_file_temp, "w") as f:
                f.write(self._lockbox_config.model_dump_json())
            env["LOCKBOX_CONFIG_PATH"] = self._lockbox_config_file_temp

        # Set up signing key file
        if self._lockbox_signing_key is not None:
            self._lockbox_signing_key_file = tempfile.mktemp()
            with open(self._lockbox_signing_key_file, "w") as f:
                f.write(self._lockbox_signing_key)
            env["LOCKBOX_SIGNING_KEY_FILE"] = self._lockbox_signing_key_file

        self._start_gunicorn("lockbox.app:app", env)

    def stop(self) -> None:
        self._stop_gunicorn()
        if self._lockbox_config_file_temp is not None:
            if os.path.exists(self._lockbox_config_file_temp):
                os.remove(self._lockbox_config_file_temp)
            self._lockbox_config_file_temp = None
        if self._lockbox_signing_key_file is not None:
            if os.path.exists(self._lockbox_signing_key_file):
                os.remove(self._lockbox_signing_key_file)
            self._lockbox_signing_key_file = None


def wait_for_condition(condition: Callable[[], bool], timeout: float = 5.0) -> None:
    start_time = time.time()
    while not condition():
        if time.time() - start_time > timeout:
            raise Exception("Timeout waiting for condition")
        time.sleep(0.25)
