import enum
import json
import logging
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, field_validator


class CredentialType(str, enum.Enum):
    BASIC = "basic"
    BEARER = "bearer"
    HEADERS = "headers"


class BasicAuthCredentialConfig(BaseModel):
    type: Literal[CredentialType.BASIC] = CredentialType.BASIC
    username: str
    password: str


class BearerTokenCredentialConfig(BaseModel):
    type: Literal[CredentialType.BEARER] = CredentialType.BEARER
    token: str


class HeadersCredentialConfig(BaseModel):
    type: Literal[CredentialType.HEADERS] = CredentialType.HEADERS
    headers: dict[str, str]


class ServiceConfig(BaseModel):
    base_url: str
    credential: (
        BasicAuthCredentialConfig
        | BearerTokenCredentialConfig
        | HeadersCredentialConfig
        | None
    ) = None
    valid_audiences: list[str] | None = None
    requires_service_token: bool | None = True
    # Connect timeout in seconds. None to disable. Default: 5
    connect_timeout: float | None = 5
    # Read timeout in seconds. None to disable. Default: 30
    read_timeout: float | None = 30
    # Whether to follow redirects. Default: False for security
    allow_redirects: bool = False

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: str) -> str:
        """Validate and normalize base_url.

        - Ensures URL has a scheme (http:// or https://)
        - Defaults to https:// if no scheme provided
        - Warns if http:// is used (security concern)
        - Strips trailing slashes for consistency

        Examples:
            "api.github.com" -> "https://api.github.com"
            "http://localhost:8000" -> "http://localhost:8000" (with warning)
            "https://api.example.com/" -> "https://api.example.com"
        """
        logger = logging.getLogger(__name__)

        # Strip trailing slashes first
        v = v.rstrip("/")

        # Parse the URL
        parsed = urlparse(v)

        # If no scheme OR if there's no netloc (which means urlparse misinterpreted
        # domain:port as scheme:path), default to https
        if not parsed.scheme or not parsed.netloc:
            # Check if this looks like it was misparsed (e.g., "localhost:8000" -> scheme='localhost')
            if parsed.scheme and not parsed.netloc and parsed.path:
                # This was likely "domain:port" misparsed as "scheme:path"
                # Reconstruct as https://domain:port
                original = v
                v = f"https://{original}"
                parsed = urlparse(v)
                logger.info(
                    f"No scheme provided for base_url '{original}', defaulting to https://"
                )
            elif not parsed.scheme:
                # No scheme at all, add https://
                original = v
                v = f"https://{v}"
                parsed = urlparse(v)
                logger.info(
                    f"No scheme provided for base_url '{original}', defaulting to https://"
                )

        # Validate scheme is http or https
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"Invalid URL scheme '{parsed.scheme}' in base_url. "
                f"Only 'http' and 'https' are supported. "
                f"If you intended to use a domain without a scheme, it will be treated as https."
            )

        # Warn if using http (security concern)
        if parsed.scheme == "http":
            logger.warning(
                f"base_url uses 'http://' scheme which is insecure. "
                f"Consider using 'https://' instead: {v}"
            )

        # Validate that we have a netloc (domain)
        if not parsed.netloc:
            raise ValueError(
                f"Invalid base_url '{v}': missing domain name. "
                f"Expected format: 'https://api.example.com' or 'api.example.com'"
            )

        return v


class AuditLogProviderType(str, enum.Enum):
    LOCAL_DIR = "local_dir"


class LocalDirAuditLogConfig(BaseModel):
    type: Literal[AuditLogProviderType.LOCAL_DIR] = AuditLogProviderType.LOCAL_DIR
    root_dir: str


class Config(BaseModel):
    services: dict[str, ServiceConfig]
    audit_log: LocalDirAuditLogConfig | None = None

    def get_service_config(self, service: str) -> ServiceConfig | None:
        try:
            return self.services[service]
        except KeyError:
            return None


def load_config(config_file: str) -> Config:
    with open(config_file) as f:
        data = json.load(f)
        return Config(**data)
