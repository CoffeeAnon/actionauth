"""Command registry — the equivalent of a Spring service map.

Each command module calls @command(name=..., hitl=...) at class definition
time, which adds the class to REGISTRY. Dispatcher.execute() looks up the
name and instantiates it. There is no reflection or classpath scanning —
just a dict populated at import time.
"""
from abc import ABC, abstractmethod
from actionauth.core.client import BridgeClient

REGISTRY: dict[str, type] = {}


class BaseCommand(ABC):
    name: str
    hitl: bool

    @abstractmethod
    def execute(self, client: BridgeClient, **kwargs) -> list[dict]:
        ...


def command(name: str, hitl: bool):
    def decorator(cls: type) -> type:
        cls.name = name
        cls.hitl = hitl
        REGISTRY[name] = cls
        return cls
    return decorator
