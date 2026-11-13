"""Recon parsing tests using a local file:// free approach (no network)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hunter4 import hunt  # noqa: E402
from hunter4.scope import Scope  # noqa: E402
from hunter4.tools import FindingsStore, ToolBox  # noqa: E402


class FakeBox(ToolBox):
    """ToolBox whose fetch returns canned HTML without any network."""

    def __init__(self, html: str, meta: dict | None = None):
        super().__init__(
            scope=Scope.from_target("example.com"),
            findings=FindingsStore(Path("/tmp")),
        )
        self._html = html
        self._meta = meta or {
            "status": 200,
            "url": "https://example.com/",
            "headers": {
                "Server": "nginx",
                "Content-Security-Policy": "default-src 'self'",
            },
        }

    def fetch(self, url, method="GET", headers=None, body=""):
        allowed, reason = self.scope.allows(url)
        if not allowed:
            return {"scope_denied": True, "url": url, "reason": reason}, ""
        return dict(self._meta, url=url), self._html


def test_recon_extracts_surface():
    html = """
    <html><head><title>  Acme App  </title></head><body>
      <a href="/product?id=1">P</a>
      <a href="https://evil.test/x">out</a>
      <script src="/static/app.js"></script>
      <script>fetch('/api/v1/orders?user_id=1')</script>
      <form action="/login" method="post"><input name="u"></form>
    </body></html>
    """
    box = FakeBox(html)
    data = hunt.recon("example.com", box.scope, box)

    assert data["title"] == "Acme App"
    assert data["server"] == "nginx"
    assert data["security_headers"]["content-security-policy"] == "default-src 'self'"
    assert data["security_headers"]["x-frame-options"] == "MISSING"
    assert any("product" in e for e in data["endpoints"])
    assert any("api/v1/orders" in e for e in data["endpoints"])
    assert "/static/app.js" in " ".join(data["scripts"])
    assert all("evil.test" not in e for e in data["endpoints"])
    assert data["forms"][0]["method"] == "POST"
    assert "id" in data["parameters"] and "user_id" in data["parameters"]


def test_recon_denied_scope_yields_empty_surface():
    box = FakeBox("<html></html>")
    box.scope.out_of_scope.append("example.com")
    data = hunt.recon("example.com", box.scope, box)
    assert data["status"] is None
    assert data["endpoints"] == []
