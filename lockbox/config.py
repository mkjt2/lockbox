import enum
import json

from pydantic import BaseModel


class CredentialType(enum.Enum):
    BASIC = "basic"
    BEARER = "bearer"
    HEADERS = "headers"


class BasicAuthCredential(BaseModel):
    type: CredentialType = CredentialType.BASIC
    username: str
    password: str


class BearerTokenCredential(BaseModel):
    type: CredentialType = CredentialType.BEARER
    token: str


class HeadersCredential(BaseModel):
    type: CredentialType = CredentialType.HEADERS
    headers: dict[str, str]


class Service(BaseModel):
    base_url: str
    credential: BasicAuthCredential | BearerTokenCredential | HeadersCredential | None = (
        None
    )
    valid_audiences: list[str] | None = None
    requires_service_token: bool | None = True


class Config(BaseModel):
    services: dict[str, Service]

    def get_service_config(self, service: str) -> Service | None:
        try:
            return self.services[service]
        except KeyError:
            return None


def load_config(config_file: str) -> Config:
    with open(config_file) as f:
        data = json.load(f)
        return Config(**data)
