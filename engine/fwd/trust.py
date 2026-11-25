"""Trust evaluation for forwarded request metadata."""

import ipaddress
from collections.abc import Mapping
from functools import lru_cache

DEFAULT_MAX_HOPS = 3
_XFF = "x-forwarded-for"
_XFP = "x-forwarded-proto"

__all__ = [
    "parse_chain",
    "trusted",
    "client_ip",
    "proto_of",
    "merge_headers",
    "check_limit",
    "validate_request",
    "forwarded_batch",
]


def _as_values(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, set):
        # Sort so repeated-header merging is deterministic regardless of
        # interpreter hash randomization.
        return sorted(value, key=str)
    return [value]


def _header_values(headers, name):
    if not headers:
        return []
    if isinstance(headers, Mapping):
        values = []
        for key, value in headers.items():
            if str(key).strip().lower() == name:
                values.extend(_as_values(value))
        return [str(value) for value in values]
    if isinstance(headers, str):
        return [headers]
    return [str(value) for value in headers]


def _limit_from_policy(policy):
    raw = DEFAULT_MAX_HOPS
    if isinstance(policy, Mapping):
        raw = policy.get("max_hops", DEFAULT_MAX_HOPS)
    elif policy is not None:
        raw = policy
    try:
        limit = int(raw)
    except (TypeError, ValueError):
        limit = DEFAULT_MAX_HOPS
    return max(0, limit)


def _request_limit(request):
    if request.get("policy") is not None:
        return _limit_from_policy(request.get("policy"))
    if request.get("max_hops") is not None:
        return _limit_from_policy(request.get("max_hops"))
    return DEFAULT_MAX_HOPS


@lru_cache(maxsize=128)
def _parse_network(text):
    # strict=False accepts bare host addresses (e.g. "10.0.0.2" -> /32).
    return ipaddress.ip_network(text, strict=False)


def parse_chain(value):
    """Return the ordered hop tokens from a forwarded-chain value."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        raw = ",".join(str(item) for item in value)
    else:
        raw = str(value)
    return [part.strip() for part in raw.split(",") if part.strip()]


def trusted(addr, nets):
    """Return whether addr belongs to one of the configured networks.

    Matching is done on real IP/network semantics rather than string
    prefixes, and anything that cannot be parsed as an address is treated
    as untrusted.
    """
    text = str(addr).strip()
    if not text:
        return False
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    for net in nets or []:
        net_text = str(net).strip()
        if not net_text:
            continue
        try:
            network = _parse_network(net_text)
        except ValueError:
            continue
        if ip in network:
            return True
    return False


def client_ip(chain, peer, nets):
    """Resolve the client address for a request received from peer.

    Headers are only honoured when the direct TCP peer is a trusted proxy.
    The chain is then walked right-to-left, skipping trusted proxy hops,
    and the leftmost untrusted address is the client. A forged header
    arriving from an untrusted peer can never override the peer address.
    """
    hops = [str(hop).strip() for hop in (chain or []) if str(hop).strip()]
    if not hops:
        return peer
    if not trusted(peer, nets):
        return peer
    for hop in reversed(hops):
        if not trusted(hop, nets):
            return hop
    # Every hop claims to be a trusted proxy; fall back to the peer.
    return peer


def proto_of(value, trusted_source):
    """Return the protocol selected for a forwarded request.

    The forwarded-proto header is only accepted when it originates from a
    trusted source; anything else falls back to plain http.
    """
    if not trusted_source:
        return "http"
    text = "" if value is None else str(value).strip().lower()
    if text in ("http", "https"):
        return text
    return "http"


def merge_headers(headers):
    """Combine repeated forwarded header values into one ordered chain."""
    values = _header_values(headers, _XFF)
    if not values:
        return []
    return parse_chain(values)


def check_limit(chain, policy):
    """Apply the configured hop limit to chain by truncating excess hops."""
    hops = list(chain or [])
    limit = _limit_from_policy(policy)
    if len(hops) > limit:
        return hops[:limit]
    return hops


def validate_request(request, nets):
    """Return the problems found while checking one request."""
    req = request or {}
    headers = req.get("headers") or {}
    peer = req.get("peer", "")
    issues = []

    forwarded_values = _header_values(headers, _XFF)
    chain = merge_headers(headers)
    peer_trusted = trusted(peer, nets)
    if forwarded_values and not peer_trusted:
        issues.append("untrusted_forwarded")

    limit = _request_limit(req)
    if len(chain) > limit:
        issues.append("chain_too_long")

    proto_values = _header_values(headers, _XFP)
    if proto_values and not peer_trusted:
        issues.append("untrusted_proto")

    # Host whitelisting is independent of the forwarded-source decision:
    # it runs on its own input regardless of whether the peer is trusted.
    allowed = req.get("allowed_hosts")
    if allowed is not None:
        host = str(req.get("host", "")).strip().lower()
        allowed_hosts = {str(item).strip().lower() for item in _as_values(allowed)}
        if host not in allowed_hosts:
            issues.append("host_not_allowed")

    return issues


def forwarded_batch(requests, nets):
    """Resolve the client address for each request in a batch.

    Each request is resolved independently: headers and chains are never
    shared across entries.
    """
    results = {}
    for index, request in enumerate(requests or []):
        req = request or {}
        headers = req.get("headers") or {}
        chain = merge_headers(headers)
        peer = req.get("peer", "")
        key = str(req.get("id", index))
        results[key] = client_ip(chain, peer, nets)
    return results
