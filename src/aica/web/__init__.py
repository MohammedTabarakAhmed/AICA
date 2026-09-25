"""The web application (INT-003): static files served by the HTTP API under ``/ui``.

There is no separate server and no build step. The page is a client of the same API the
CLI's peers use, holding only the bearer token the user pastes in, so it can do nothing
the API would not let that token do.
"""

from pathlib import Path

STATIC_DIR = Path(__file__).parent / "static"

# The page loads only its own files and talks only to its own origin. With no inline
# script and no third-party origin allowed, injected markup has nothing it can run.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'self'"
)

__all__ = ["CONTENT_SECURITY_POLICY", "STATIC_DIR"]
