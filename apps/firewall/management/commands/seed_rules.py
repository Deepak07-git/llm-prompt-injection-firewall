"""Seed the Rule table from firewall_core.default_rules().

Idempotent: existing rows (matched by rule_id) are updated in place, preserving
any operator edits to `enabled`/`action` unless --force is given.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand

from apps.firewall.models import FirewallConfig, Rule
from firewall_core.rules import default_rules


class Command(BaseCommand):
    help = "Seed built-in firewall rules into the database."

    def add_arguments(self, parser):
        parser.add_argument("--force", action="store_true",
                            help="Overwrite existing rows' pattern/severity/etc.")

    def handle(self, *args, **opts):
        force = opts["force"]
        created = updated = 0
        for cr in default_rules():
            row, was_created = Rule.objects.get_or_create(
                rule_id=cr.id,
                defaults=dict(
                    pattern=cr.pattern, severity=cr.severity, category=cr.category,
                    description=cr.description, mitigation=cr.mitigation,
                    atlas=cr.atlas, enabled=cr.enabled, builtin=True,
                ),
            )
            if was_created:
                created += 1
            elif force:
                row.pattern = cr.pattern
                row.severity = cr.severity
                row.category = cr.category
                row.description = cr.description
                row.mitigation = cr.mitigation
                row.atlas = cr.atlas
                row.builtin = True
                row.save()
                updated += 1

        FirewallConfig.load()  # ensure the singleton config row exists
        self.stdout.write(self.style.SUCCESS(
            f"Seeded rules: {created} created, {updated} updated, "
            f"{Rule.objects.count()} total."
        ))
