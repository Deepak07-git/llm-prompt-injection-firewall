from django.conf import settings
from django.db import models


class Conversation(models.Model):
    """Only firewall-approved turns are stored; client-supplied roles are rejected."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    conversation_id = models.CharField(max_length=80)
    messages = models.JSONField(default=list)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(
            fields=["user", "conversation_id"], name="chat_user_conversation"
        )]
