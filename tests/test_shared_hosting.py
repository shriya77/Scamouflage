"""
Tests for Shared Hosting Wildcard & PSL Isolation Mitigation
"""
import pytest
from backend import blocklist_route as B
from labels import feeds as Feeds
from model import features as F
from model import stage0 as S0


def test_psl_isolation_across_modules():
    platforms = [
        "fake-usps.pages.dev",
        "ezpass-toll.web.app",
        "scam-bill.workers.dev",
        "phish-account.github.io",
    ]
    for host in platforms:
        # Feeds registered domain must isolate tenant
        assert Feeds.registered_domain(host) == host, f"Feeds failed for {host}"

        # Stage 0 registered domain must isolate tenant
        assert S0.registered_domain(host) == host, f"Stage 0 failed for {host}"

        # Features registered domain must isolate tenant
        assert F.registered_domain(host) == host, f"Features failed for {host}"


def test_blocklist_targets_never_wildcards_shared_platform():
    targets = B.targets_for("fake-usps.pages.dev", set())
    assert len(targets) > 0
    # Every emitted target must have match_subdomains = False
    for target_name, match_sub in targets:
        assert target_name == "fake-usps.pages.dev"
        assert match_sub is False, "Platform tenant must not have match_subdomains=True"


def test_blocklist_targets_rejects_platform_apex():
    # Platform apexes must never be emitted into the blocklist
    for apex in ["pages.dev", "web.app", "workers.dev", "github.io"]:
        assert B.targets_for(apex, set()) == [], f"Apex {apex} was unexpectedly emitted"
