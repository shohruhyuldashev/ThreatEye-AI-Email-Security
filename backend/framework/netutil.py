"""
Offline-safe URL / domain extraction.

tldextract and urlextract both try to fetch a remote list (public-suffix list /
IANA TLDs) on first use. In a locked-down or air-gapped container that network
call fails and crashes analysis. Here we configure them to use their **bundled
snapshots only** (no runtime fetch), with a regex fallback for URL extraction, so
the detector works with zero outbound network.
"""
from __future__ import annotations

import logging
import re

import tldextract

logger = logging.getLogger(__name__)

# Empty suffix_list_urls => never fetch at runtime; use the packaged snapshot.
_TLD = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)

_URL_RE = re.compile(r"""https?://[^\s<>"'`)\]]+""", re.IGNORECASE)

_URL_EXTRACTOR = None
try:
    from urlextract import URLExtract

    _URL_EXTRACTOR = URLExtract()
    # Never trigger an online refresh of the TLD list.
    try:
        _URL_EXTRACTOR.update_when_older(36500)
    except Exception:
        pass
except Exception as e:  # pragma: no cover - only when urlextract can't init offline
    logger.warning("URLExtract unavailable, falling back to regex URL extraction: %s", e)


def tld_extract(value: str):
    """tldextract.extract() equivalent that never hits the network."""
    return _TLD(value or "")


def find_urls(text: str) -> list[str]:
    """Extract URLs from text; robust when urlextract can't load its list."""
    text = text or ""
    if _URL_EXTRACTOR is not None:
        try:
            return _URL_EXTRACTOR.find_urls(text)
        except Exception:
            pass
    return _URL_RE.findall(text)
