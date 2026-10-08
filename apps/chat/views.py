from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.shortcuts import render
from drf_spectacular.utils import extend_schema
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.chat.models import Conversation
from apps.chat.serializers import ChatSerializer
from apps.chat.services import run_chat


class ChatView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(request=ChatSerializer, summary="Chat through the input and output firewall")
    def post(self, request):
        serializer = ChatSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            payload, status = run_chat(request, **serializer.validated_data)
        except Exception:
            # Fail closed, including DB/audit failures. DEBUG pages must not expose
            # raw model output, request locals or credentials.
            return Response({"success": False, "message": "Chat service is temporarily unavailable.",
                             "error": "chat_unavailable"}, status=503)
        headers = {"Retry-After": str(payload["retry_after"])} if status == 429 else {}
        return Response(payload, status=status, headers=headers)


class ConversationView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, conversation_id):
        lock = f"chat:lock:{request.user.pk}:{conversation_id}"
        if not cache.add(lock, "clear", timeout=30):
            return Response({"success": False, "message": "Wait for the current message to finish."}, status=409)
        try:
            Conversation.objects.filter(user=request.user, conversation_id=conversation_id).delete()
            return Response({"success": True})
        finally:
            cache.delete(lock)


@login_required
def chat_page(request):
    return render(request, "dashboard/chat.html", {"active": "chat", "model": settings.OLLAMA_MODEL})
