from actionauth.core.client import InMemoryTaskStore
from actionauth.core.registry import BaseCommand, command


@command(name="list-tasks", hitl=False)
class ListTasks(BaseCommand):
    def execute(self, client: InMemoryTaskStore, **kwargs) -> list[dict]:
        return client.list()
