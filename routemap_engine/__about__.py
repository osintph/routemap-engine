"""The engine's own name and version. The desktop app and FalconEye name themselves."""

NAME = "routemap-engine"
REPO_SLUG = "osintph/routemap-engine"
REPO_URL = f"https://github.com/{REPO_SLUG}"

__version__ = "0.4.1"

# Upstreams see this product token unless the caller passes its own User-Agent,
# so a complaint about traffic reaches the project rather than nobody.
USER_AGENT_PRODUCT = f"{NAME}/{__version__}"
USER_AGENT = f"{USER_AGENT_PRODUCT} (+{REPO_URL})"
