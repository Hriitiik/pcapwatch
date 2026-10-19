import random
import string

from pcapwatch.models import DNSQuery
from pcapwatch.detectors.dns import detect_dns, entropy, split_name


def rand_label(n, rng):
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def test_entropy_ordering():
    assert entropy("aaaaa") == 0
    assert entropy("google") < entropy("x93jnhdia01387nfdvo0134a")


def test_tunneling_detected():
    rng = random.Random(1)
    qs = [
        DNSQuery(100 + i, "10.0.0.5", f"{rand_label(40, rng)}.evil.com")
        for i in range(30)
    ]
    findings = detect_dns(qs)
    assert any(
        f.rule == "dns_tunneling" and f.attack_id == "T1071.004" for f in findings
    )


def test_dga_detected():
    rng = random.Random(2)
    qs = [
        DNSQuery(100 + i, "10.0.0.5", f"{rand_label(16, rng)}.com") for i in range(15)
    ]
    findings = detect_dns(qs)
    assert any(f.rule == "dga" for f in findings)


def test_normal_dns_not_detected():
    names = [
        "google.com",
        "www.google.com",
        "github.com",
        "api.github.com",
        "wikipedia.org",
        "uni-stuttgart.de",
    ] * 10
    qs = [DNSQuery(100 + i, "10.0.0.5", n) for i, n in enumerate(names)]
    assert detect_dns(qs) == []


def test_split_multipart_tld():
    assert split_name("abc.xyz.example.co.uk") == (
        "example.co.uk",
        "abc.xyz",
        "example",
    )
    assert split_name("www.google.com") == ("google.com", "www", "google")
    assert split_name("localhost") is None
