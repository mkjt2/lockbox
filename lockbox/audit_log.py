import dataclasses
import json
import os
import typing
import uuid
from datetime import datetime, timezone
from pathlib import Path

from lockbox.config import LocalDirAuditLogConfig


def _validate_and_sanitize_path(root_dir: str, service_name: str, *path_parts: str) -> str:
    """
    Validate that a constructed file path stays within the root directory.
    
    Args:
        root_dir: The root directory that all paths must stay within
        service_name: The service name (potentially from user input)
        *path_parts: Additional path components to append
        
    Returns:
        A safe, absolute file path that is guaranteed to be within root_dir
        
    Raises:
        ValueError: If the service name is invalid or path traversal is detected
    """
    # Validate service name
    if not service_name:
        raise ValueError("Service name cannot be empty or None")
    
    root_path = Path(root_dir).resolve()
    intended_path = root_path / service_name
    for part in path_parts:
        intended_path = intended_path / part
    
    resolved_path = intended_path.resolve()
    
    # Ensure the resolved path is within the root directory
    try:
        resolved_path.relative_to(root_path)
        return str(resolved_path)
    except ValueError:
        # Path traversal detected - throw an exception
        raise ValueError(f"Invalid service name '{service_name}': potential path traversal detected")


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
        try:
            # Validate the service name first (using dummy path parts for validation only)
            _validate_and_sanitize_path(self._root_dir, event.service_name, "dummy", "dummy")
        except ValueError as e:
            # Log the security violation and abort logging
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"SECURITY VIOLATION: {e} - Service name: '{event.service_name}' - Request ID: {event.request_id}")
            return  # Do not proceed with logging the event
        
        # If validation passes, proceed with normal logging
        d = datetime.fromtimestamp(int(event.ts), tz=timezone.utc)
        year_month_day = d.strftime("%Y-%m-%d")
        hour_minute_second = d.strftime("%H-%M-%S")
        uuid_suffix = str(uuid.uuid4())
        basename = f"{hour_minute_second}-{uuid_suffix}.json"
        
        # Use the validated path function to prevent path traversal
        event_file_path = _validate_and_sanitize_path(
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
