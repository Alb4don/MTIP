import pytest

from mtip.normalize import (
    NormalizationError, NormalizedIndicator, core_family_name, distinctive_tokens, is_shared_infrastructure, normalize,
    package_namespace, refang, registered_domain, root_of, stix_path_to_kind,
)


@pytest.mark.parametrize("raw,expected", [
    ("hxxps://evil[.]example[.]com/a", "https://evil.example.com/a"),
    ("evil(.)com", "evil.com"),
    ("user[@]mail[dot]com", "user@mail.com"),
])
def test_refang(raw, expected):
    assert refang(raw) == expected


def test_domain_normalisation_folds_case_trailing_dot_and_idna():
    assert normalize("domain", "WWW.Example.COM.").value == "www.example.com"
    assert normalize("domain", "bücher.de").value == "xn--bcher-kva.de"
    assert normalize("domain", "*.wild.example.org").value == "wild.example.org"


def test_domain_that_is_an_ip_becomes_ip_indicator():
    ind = normalize("domain", "8.8.8.8")
    assert ind.kind == "ipv4" and ind.value == "8.8.8.8"


@pytest.mark.parametrize("bad", ["", "nodot", "-bad-.com", "a..b.com", "x" * 300 + ".com", "evil.com\n", "123.456"])
def test_invalid_domains_rejected(bad):
    with pytest.raises(NormalizationError):
        normalize("domain", bad)


def test_url_canonicalisation():
    assert normalize("url", "HTTP://Evil.COM:80/path?q=1#frag").value == "http://evil.com/path?q=1"
    assert normalize("url", "https://evil.com:8443").value == "https://evil.com:8443/"
    assert normalize("url", "hxxp://evil[.]com/x").value == "http://evil.com/x"
    with pytest.raises(NormalizationError):
        normalize("url", "javascript:alert(1)")
    with pytest.raises(NormalizationError):
        normalize("url", "http://evil.com:99999/")


def test_ipv6_compressed():
    assert normalize("ipv6", "2001:0db8:0000:0000:0000:0000:0000:0001").value == "2001:db8::1"


def test_hashes_lowercased_and_length_checked():
    h = "A" * 64
    assert normalize("sha256", h).value == "a" * 64
    with pytest.raises(NormalizationError):
        normalize("sha256", "abc")
    with pytest.raises(NormalizationError):
        normalize("md5", "z" * 32)


def test_android_package_names():
    assert normalize("app_id", "com.example.spy").value == "com.example.spy"
    for bad in ("com", "1com.x", "com..x", "com.x y"):
        with pytest.raises(NormalizationError):
            normalize("app_id", bad)


def test_unknown_kind_rejected():
    with pytest.raises(NormalizationError):
        normalize("nope", "x")


def test_non_text_rejected():
    with pytest.raises(NormalizationError):
        normalize("domain", 42)


def test_registered_domain_uses_public_suffix_list():
    assert registered_domain("a.b.example.co.uk") == "example.co.uk"
    assert registered_domain("tenant1.appspot.com") == "tenant1.appspot.com"
    assert registered_domain("x.y.example.com") == "example.com"
    assert registered_domain("co.uk") is None


def test_shared_infrastructure_is_root_aware():
    assert is_shared_infrastructure("aliyuncs.com")
    assert is_shared_infrastructure("zendesk.com")
    assert is_shared_infrastructure(None)
    assert not is_shared_infrastructure("thetruthspy.com")
    assert root_of(NormalizedIndicator("domain", "bucket.oss-us-west-1.aliyuncs.com")) == "aliyuncs.com"


def test_package_namespace_ignores_platform_vendors():
    assert package_namespace("com.thetruthspy.app") == "com.thetruthspy"
    assert package_namespace("com.google.android.gms") is None
    assert package_namespace("com.app.anything") is None


def test_distinctive_tokens_drop_generic_words():
    tokens = distinctive_tokens(NormalizedIndicator("domain", "api.contents-domain.com"))
    assert "domain" not in tokens and "contents" not in tokens
    assert "copy9" in distinctive_tokens(NormalizedIndicator("domain", "copy9.com"))
    assert "thetruthspy" in distinctive_tokens(NormalizedIndicator("domain", "x.thetruthspy.com"))
    assert distinctive_tokens(NormalizedIndicator("domain", "docs.google.com")) == frozenset()


def test_core_family_name_strips_generic_terms():
    assert core_family_name("pegasus for android") == "pegasus"
    assert core_family_name("androidspy") == ""
    assert core_family_name("phonemonitor") == ""
    assert core_family_name("spynote rat") == "note"


@pytest.mark.parametrize("otype,path,kind", [
    ("domain-name", ("value",), "domain"),
    ("file", ("hashes", "SHA-256"), "sha256"),
    ("file", ("hashes", "sha256"), "sha256"),
    ("app", ("id",), "app_id"),
    ("app", ("cert", "sha256"), "cert_sha256"),
    ("x509-certificate", ("hashes", "SHA-1"), "cert_sha1"),
    ("mutex", ("name",), None),
])
def test_stix_path_mapping(otype, path, kind):
    assert stix_path_to_kind(otype, path) == kind
