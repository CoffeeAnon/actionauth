"""Smoke tests for ``actionauth walkthrough`` (the narrated sequence diagram).

Regression guard for the SyntaxError the rename to ``actionauth`` shipped with:
``walkthrough.py`` carried nested same-quote text inside string literals
(``"docs/architecture.md "Threat" model ...``), which is invalid Python and made
``import actionauth.walkthrough`` raise. The README documents
``actionauth walkthrough --tier 2`` (README.md "Interactive walkthrough", and
the walkthrough section of ``docs/architecture.md``), so a broken import here
breaks a documented core feature.

These tests exercise the real walkthrough in-process (no mocks): the point is
that the module imports and every narrated step reaches its post-conditions on
both tiers. They fail loudly at collection with SyntaxError if the file ever stops
parsing again.
"""
from __future__ import annotations

import actionauth.cli as cli
from actionauth.walkthrough import walkthrough_a2a


def test_walkthrough_module_is_importable():
    """The syntax-error regression: importing the module must not raise."""
    assert callable(walkthrough_a2a)


def test_walkthrough_tier2_completes(capsys):
    """Tier 2 (external delegation authority + JWT mint) walks to the end."""
    assert walkthrough_a2a(tier=2, pause=False) == 0
    out = capsys.readouterr().out
    assert "Walkthrough complete." in out
    # Post-conditions the walkthrough itself checks, echoed in narration.
    assert "deleted" in out
    assert "survives" in out


def test_walkthrough_tier1_completes(capsys):
    """Tier 1 (in-process HMAC authority) walks to the end too."""
    assert walkthrough_a2a(tier=1, pause=False) == 0
    assert "Walkthrough complete." in capsys.readouterr().out


def test_cli_walkthrough_entrypoint_returns_zero(capsys):
    """The documented ``actionauth walkthrough --tier 2`` path through the CLI.

    Guards ``actionauth.cli.main``'s deferred import of the walkthrough module,
    which is where the SyntaxError surfaced for a user following the README.
    """
    assert cli.main(["walkthrough", "--tier", "2"]) == 0
    out = capsys.readouterr().out
    assert "Walkthrough complete." in out
    # The two lines that carried the unescaped quotes render with the inner
    # quotes intact (escaping preserved the author's text, not deleted it).
    assert '"A2A" flow.' in out
    assert 'docs/architecture.md "Threat" model' in out
