from actionauth.core.client import InMemoryTaskStore
from actionauth.core.registry import BaseCommand, command


@command(name="create-task", hitl=False)
class CreateTask(BaseCommand):
    def execute(
        self,
        client: InMemoryTaskStore,
        *,
        title: str,
        description: str = "",
        **kwargs,
    ) -> list[dict]:
        return [client.create(title=title, description=description)]
