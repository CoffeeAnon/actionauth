"""Resource-server client for the reference's task-tracker example.

The reference ships an in-memory task store as the example resource server.
A production deployment would replace ``InMemoryTaskStore`` with an HTTP
client against a real task-tracker service, or with whatever client shape
the deployment's actual resource server requires.

The dispatcher depends only on:
  - the ``BridgeClient`` symbol being importable
  - ``ApiError`` being raisable from the client

Both are preserved across implementations.
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import asdict, dataclass


class ApiError(Exception):
    """Raised by client implementations on resource-server failure."""

    def __init__(self, status_code: int, body: str):
        super().__init__(f"{status_code}: {body}")
        self.status_code = status_code
        self.body = body


@dataclass
class Task:
    task_id: str
    title: str
    description: str = ""
    status: str = "open"


class InMemoryTaskStore:
    """Thread-safe in-memory task store. Used by the reference's example commands.

    A real deployment would replace this with an HTTP client (httpx etc.)
    against the actual task-tracker resource server.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, Task] = {}
        self._lock = threading.Lock()

    def list(self) -> list[dict]:
        with self._lock:
            return [asdict(t) for t in self._tasks.values()]

    def get(self, task_id: str) -> dict:
        with self._lock:
            t = self._tasks.get(task_id)
        if t is None:
            raise ApiError(404, f"task {task_id} not found")
        return asdict(t)

    def create(self, title: str, description: str = "") -> dict:
        task = Task(task_id=str(uuid.uuid4())[:8], title=title, description=description)
        with self._lock:
            self._tasks[task.task_id] = task
        return asdict(task)

    def update(self, task_id: str, **fields) -> dict:
        with self._lock:
            t = self._tasks.get(task_id)
            if t is None:
                raise ApiError(404, f"task {task_id} not found")
            for k, v in fields.items():
                if v is not None and hasattr(t, k):
                    setattr(t, k, v)
            return asdict(t)

    def delete(self, task_id: str) -> dict:
        with self._lock:
            t = self._tasks.pop(task_id, None)
        if t is None:
            raise ApiError(404, f"task {task_id} not found")
        return asdict(t)


# The dispatcher depends on this symbol; the reference exports the in-memory
# store under the canonical name. Production deployments override this binding
# (via a config / DI container) with their HTTP client.
BridgeClient = InMemoryTaskStore
