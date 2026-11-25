from engine.fwd.trust import (
    check_limit,
    client_ip,
    forwarded_batch,
    proto_of,
)

PROXIES = ["10.0.0.0/8"]


def test_single_proxy_resolves_client_address():
    assert client_ip(["203.0.113.7", "10.0.0.2"], "10.0.0.2", PROXIES) == "203.0.113.7"


def test_forged_header_is_ignored_for_untrusted_peer():
    assert client_ip(["203.0.113.7", "10.0.0.2"], "192.0.2.44", PROXIES) == "192.0.2.44"


def test_overlong_chain_is_truncated():
    chain = ["203.0.113.7", "10.0.0.9", "10.0.0.2"]
    assert check_limit(chain, {"max_hops": 2}) == ["203.0.113.7", "10.0.0.9"]


def test_untrusted_source_cannot_override_protocol():
    assert proto_of("https", False) == "http"
    assert proto_of("https", True) == "https"


def test_batch_requests_are_independent():
    requests = [
        {
            "id": "first",
            "peer": "10.0.0.2",
            "headers": {"X-Forwarded-For": ["203.0.113.7"]},
        },
        {
            "id": "second",
            "peer": "10.0.0.3",
            "headers": {"X-Forwarded-For": ["198.51.100.8"]},
        },
    ]
    assert forwarded_batch(requests, PROXIES) == {
        "first": "203.0.113.7",
        "second": "198.51.100.8",
    }