from actionauth.core.client import InMemoryTaskStore
from actionauth.core.registry import BaseCommand, command


@command(name="update-task", hitl=False)
class UpdateTask(BaseCommand):
    def execute(
        self,
        client: InMemoryTaskStore,
        *,
        task_id: str,
        title: str | None = None,
        description: str | None = None,
        status: str | None = None,
        **kwargs,
    ) -> list[dict]:
        return [client.update(task_id, title=title, description=description, status=status)]
