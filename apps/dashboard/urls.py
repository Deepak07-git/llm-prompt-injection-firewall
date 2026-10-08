from __future__ import annotations

from django.urls import path

from apps.dashboard import views
from apps.chat.views import chat_page

app_name = "dashboard"

urlpatterns = [
    path("chat/", chat_page, name="chat"),
    path("", views.overview, name="overview"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("logs/", views.logs, name="logs"),
    path("logs/<int:pk>/", views.log_detail, name="log_detail"),
    path("rules/", views.rules, name="rules"),
    path("analytics/", views.analytics, name="analytics"),
    path("tester/", views.tester, name="tester"),
]
