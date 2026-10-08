from django.conf import settings
from rest_framework import serializers


class ChatSerializer(serializers.Serializer):
    message = serializers.CharField(max_length=settings.CHAT_MAX_MESSAGE_CHARS,
                                    trim_whitespace=False)
    conversation_id = serializers.RegexField(r"^[A-Za-z0-9_-]{1,80}$", required=False)

    def validate(self, attrs):
        if set(self.initial_data) - {"message", "conversation_id"}:
            raise serializers.ValidationError("Only message and conversation_id are accepted.")
        if not attrs["message"].strip():
            raise serializers.ValidationError("Message cannot be empty.")
        return attrs
