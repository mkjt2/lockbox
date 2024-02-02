import dataclasses
import json
import os
import typing
import uuid
from datetime import datetime, timezone

from lockbox.config import LocalDirAuditLogConfig


@dataclasses.dataclass
class Event:
    ts: float
    service_name: str
    request_id: str
    event_name: str
    payload: dict[str, typing.Any]

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "ts": self.ts,
            "event_name": self.event_name,
            "service_name": self.service_name,
            "request_id": self.request_id,
            "payload": self.payload,
        }


class AuditLogProvider(typing.Protocol):
    def log_service_event(self, event: Event) -> None:
        ...


class LocalDirectoryAuditLogProvider(AuditLogProvider):
    def __init__(self, root_dir: str):
        self._root_dir = root_dir

    def log_service_event(self, event: Event) -> None:
        d = datetime.fromtimestamp(int(event.ts), tz=timezone.utc)
        year_month_day = d.strftime("%Y-%m-%d")
        hour_minute_second = d.strftime("%H-%M-%S")
        uuid_suffix = str(uuid.uuid4())
        basename = f"{hour_minute_second}-{uuid_suffix}.json"
        event_file_path = os.path.join(
            self._root_dir, event.service_name, year_month_day, basename
        )
        event_file_dir = os.path.dirname(event_file_path)
        os.makedirs(event_file_dir, exist_ok=True)

        with open(event_file_path, "w") as f:
            # indent for readability, but machine consumers should not depend on this
            json.dump(event.as_dict(), f, indent=4)


def get_audit_log_provider(
    audit_log_config: LocalDirAuditLogConfig,
) -> AuditLogProvider:
    if isinstance(audit_log_config, LocalDirAuditLogConfig):
        return LocalDirectoryAuditLogProvider(audit_log_config.root_dir)
    raise ValueError("Invalid audit log provider config")
