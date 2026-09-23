from actionauth.core.client import InMemoryTaskStore
from actionauth.core.registry import BaseCommand, command


@command(name="delete-task", hitl=True)
class DeleteTask(BaseCommand):
    """Destructive — HITL-gated. The dispatcher refuses to execute without a
    valid approval token whose HMAC digest covers the exact task_id passed in.
    """

    def execute(self, client: InMemoryTaskStore, *, task_id: str, **kwargs) -> list[dict]:
        return [client.delete(task_id)]
