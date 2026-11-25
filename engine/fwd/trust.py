"""Trust evaluation for forwarded request metadata."""

import ipaddress
from collections.abc import Mapping

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
    if isinstance(value, (list, tuple, set)):
        return list(value)
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


def _is_ip(value):
    try:
        ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return True


def parse_chain(value):
    """Return the ordered hop tokens from a forwarded-chain value."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        raw = ",".join(str(item) for item in value)
    else:
        raw = str(value)
    return [part for part in raw.split(",") if part]


def trusted(addr, nets):
    """Return whether addr belongs to one of the configured networks."""
    text = str(addr).strip()
    if not text:
        return False
    for net in nets or []:
        base = str(net).split("/", 1)[0].strip()
        if not base:
            continue
        if "." in base:
            prefix = base.rsplit(".", 1)[0]
        else:
            prefix = base
        if text.startswith(prefix):
            return True
    return False


def client_ip(chain, peer, nets):
    """Resolve the client address for a request received from peer."""
    hops = list(chain or [])
    if not hops:
        return peer
    if trusted(peer, nets):
        return hops[-1]
    return hops[0]


def proto_of(value, trusted):
    """Return the protocol selected for a forwarded request."""
    text = "" if value is None else str(value).strip().lower()
    if text in ("http", "https"):
        return text
    return "http"


def merge_headers(headers):
    """Combine repeated forwarded header values into one ordered chain."""
    values = _header_values(headers, _XFF)
    if not values:
        return []
    return parse_chain(values[0])


def check_limit(chain, policy):
    """Apply the configured hop limit to chain."""
    hops = list(chain or [])
    limit = _limit_from_policy(policy)
    if len(hops) > limit:
        return []
    return hops


def validate_request(request, nets):
    """Return the problems found while checking one request."""
    req = request or {}
    headers = req.get("headers") or {}
    peer = req.get("peer", "")
    issues = []

    forwarded_values = _header_values(headers, _XFF)
    chain = merge_headers(headers)
    if forwarded_values and not trusted(peer, nets):
        issues.append("untrusted_forwarded")

    limit = _request_limit(req)
    if len(chain) > limit:
        issues.append("chain_too_long")

    proto_values = _header_values(headers, _XFP)
    if proto_values and not trusted(peer, nets):
        issues.append("untrusted_proto")

    allowed = req.get("allowed_hosts")
    if allowed is not None:
        host = str(req.get("host", "")).strip().lower()
        allowed_hosts = {str(item).strip().lower() for item in _as_values(allowed)}
        if host not in allowed_hosts:
            issues.append("host_not_allowed")

    return issues


def forwarded_batch(requests, nets):
    """Resolve the client address for each request in a batch."""
    results = {}
    cached_chain = None
    for index, request in enumerate(requests or []):
        req = request or {}
        headers = req.get("headers") or {}
        if cached_chain is None:
            cached_chain = merge_headers(headers)
        peer = req.get("peer", "")
        key = str(req.get("id", index))
        results[key] = client_ip(cached_chain, peer, nets)
    return results