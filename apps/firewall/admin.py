from __future__ import annotations

from django.contrib import admin

from apps.firewall.models import FirewallConfig, Rule
from apps.firewall.services import bump_engine_version


@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):
    list_display = ("rule_id", "severity", "category", "action", "enabled", "builtin")
    list_filter = ("severity", "category", "enabled", "builtin")
    search_fields = ("rule_id", "pattern", "description")
    list_editable = ("enabled",)

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        bump_engine_version()


@admin.register(FirewallConfig)
class FirewallConfigAdmin(admin.ModelAdmin):
    list_display = ("__str__", "default_mode", "use_ai", "output_block_threshold", "updated_at")

    def has_add_permission(self, request) -> bool:
        return not FirewallConfig.objects.exists()

    def has_delete_permission(self, request, obj=None) -> bool:
        return False

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        bump_engine_version()
