from django.urls import path
from apps.chat.views import ChatView, ConversationView

urlpatterns = [
    path("", ChatView.as_view(), name="api-chat"),
    path("conversations/<slug:conversation_id>/", ConversationView.as_view(), name="api-chat-clear"),
]
