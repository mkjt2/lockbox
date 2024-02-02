import enum
import json
from typing import Literal

from pydantic import BaseModel


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
    credential: BasicAuthCredentialConfig | BearerTokenCredentialConfig | HeadersCredentialConfig | None = (
        None
    )
    valid_audiences: list[str] | None = None
    requires_service_token: bool | None = True


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
