from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

MAX_VALUE_LEN = 2048

KIND_DOMAIN = "domain"
KIND_URL = "url"
KIND_IPV4 = "ipv4"
KIND_IPV6 = "ipv6"
KIND_SHA256 = "sha256"
KIND_SHA1 = "sha1"
KIND_MD5 = "md5"
KIND_APP = "app_id"
KIND_CERT = "cert_sha256"
KIND_CERT_SHA1 = "cert_sha1"
KIND_EMAIL = "email"
KIND_FILE_NAME = "file_name"
KIND_FILE_PATH = "file_path"
KIND_PROCESS = "process_name"
KIND_ANDROID_PROP = "android_property"
KIND_OTHER = "other"

ALL_KINDS = (
    KIND_DOMAIN, KIND_URL, KIND_IPV4, KIND_IPV6, KIND_SHA256, KIND_SHA1, KIND_MD5, KIND_APP,
    KIND_CERT, KIND_CERT_SHA1, KIND_EMAIL, KIND_FILE_NAME, KIND_FILE_PATH, KIND_PROCESS,
    KIND_ANDROID_PROP, KIND_OTHER,
)
STRUCTURAL_KINDS = frozenset({KIND_DOMAIN, KIND_URL, KIND_APP, KIND_EMAIL})

_HASH_LEN = {KIND_MD5: 32, KIND_SHA1: 40, KIND_SHA256: 64, KIND_CERT: 64, KIND_CERT_SHA1: 40}
_HEX = re.compile(r"^[0-9a-f]+$")
_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_PACKAGE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_REFANG = [
    (re.compile(r"(?i)\bhxxps\b"), "https"),
    (re.compile(r"(?i)\bhxxp\b"), "http"),
    (re.compile(r"(?i)\bfxp\b"), "ftp"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[@\]|\[at\]|\(at\)", re.IGNORECASE), "@"),
    (re.compile(r"\[/\]"), "/"),
]

_BUILTIN_SUFFIXES = frozenset("""
com net org edu gov mil int info biz name pro mobi app dev io co me tv cc ws ru su ua by kz cn tw hk jp kr in id my sg th vn ph pk bd ir tr il ae sa eg za ng ke br ar mx cl pe uy ve ec bo py us ca uk de fr es it pt nl be ch at se no fi dk pl cz sk hu ro bg gr ie lt lv ee si hr rs ba mk al md ge am az uz eu asia top xyz online site club shop store live link click space website tech fun icu buzz vip work today world life cloud email network services support solutions agency digital media news blog win bid loan men date download stream review trade science party racing cricket accountant faith ltd group company center host press pw tk ml ga cf gq cyou rest sbs bond
co.uk org.uk ac.uk gov.uk me.uk ltd.uk plc.uk net.uk sch.uk
com.br net.br org.br gov.br edu.br art.br blog.br eco.br
com.au net.au org.au edu.au gov.au id.au
co.jp ne.jp or.jp ac.jp go.jp
co.kr or.kr ne.kr go.kr
com.cn net.cn org.cn gov.cn edu.cn ac.cn
com.tw net.tw org.tw idv.tw
com.hk net.hk org.hk
co.in net.in org.in firm.in gen.in ind.in
co.id or.id web.id go.id
com.my net.my org.my
com.sg net.sg org.sg
co.th in.th or.th
com.vn net.vn org.vn
com.ph net.ph org.ph
com.pk net.pk org.pk
com.tr net.tr org.tr gen.tr
co.il org.il net.il
com.sa net.sa org.sa
com.eg net.eg org.eg
co.za org.za net.za web.za
com.ng org.ng net.ng
co.ke or.ke
com.ar net.ar org.ar
com.mx net.mx org.mx gob.mx
co.uk.com
com.co net.co org.co
com.pe net.pe org.pe
com.ve net.ve
com.ua net.ua org.ua in.ua kiev.ua
com.ru net.ru org.ru msk.ru spb.ru
co.nz net.nz org.nz
com.pl net.pl org.pl
co.at or.at
com.es org.es nom.es
com.pt
com.gr
co.ve
appspot.com firebaseapp.com firebaseio.com web.app page.link herokuapp.com herokudns.com github.io githubusercontent.com gitlab.io blogspot.com
duckdns.org no-ip.org no-ip.biz no-ip.info ddns.net hopto.org zapto.org sytes.net serveftp.com myftp.org servebeer.com dynu.net freeddns.org
ngrok.io ngrok-free.app ngrok.app trycloudflare.com 000webhostapp.com azurewebsites.net cloudapp.net cloudapp.azure.com blob.core.windows.net
cloudfront.net s3.amazonaws.com elasticbeanstalk.com execute-api.us-east-1.amazonaws.com workers.dev pages.dev vercel.app netlify.app
glitch.me repl.co onrender.com fly.dev wixsite.com weebly.com wordpress.com myshopify.com translate.goog r.appspot.com
""".split())

SHARED_INFRA_ROOTS = frozenset("""
google.com googleapis.com gstatic.com googleusercontent.com googlesyndication.com google-analytics.com doubleclick.net
android.com youtube.com ytimg.com gmail.com goo.gl g.co
apple.com icloud.com mzstatic.com
microsoft.com live.com outlook.com office.com windows.net msftncsi.com bing.com
amazonaws.com amazon.com cloudflare.com cloudflare-dns.com akamai.net akamaihd.net akamaized.net edgekey.net edgesuite.net fastly.net
github.com facebook.com fbcdn.net instagram.com whatsapp.com whatsapp.net telegram.org t.me twitter.com x.com twimg.com
dropbox.com bit.ly tinyurl.com is.gd ow.ly pastebin.com wikipedia.org mozilla.org mozilla.net
crashlytics.com app-measurement.com firebase.com onesignal.com pushwoosh.com
aliyuncs.com myqcloud.com qcloud.com azureedge.net b-cdn.net oraclecloud.com digitaloceanspaces.com backblazeb2.com wasabisys.com
linodeobjects.com cloudfunctions.net run.app storage.googleapis.com amplifyapp.com azurefd.net cdn77.org jsdelivr.net
zendesk.com zdassets.com freshdesk.com helpscoutdocs.com intercom.io tawk.to crisp.chat zohodesk.com zoho.com squarespace.com
shopify.com wix.com godaddysites.com mailchimp.com sendgrid.net mailgun.org paypal.com stripe.com
""".split())

GENERIC_PACKAGE_NAMESPACES = frozenset("""
com.google com.android android androidx com.samsung com.sec com.qualcomm com.qti com.huawei com.xiaomi com.miui com.oppo com.vivo
com.facebook com.whatsapp org.telegram com.example com.app com.apps com.mobile com.my com.new com.test org.chromium com.microsoft
com.amazon com.twitter com.instagram com.snapchat org.mozilla io.flutter com.unity3d com.squareup
""".split())

_STOP_TOKENS = frozenset("""
com org net app apps android mobile service services update updater system sys core main client server api www mail web
cloud online free pro lite plus home info data sync secure security manager helper tools tool test demo play store
monitor tracker track phone spy spyware hidden device admin google apple official support login account
domain domains security secure content contents logger keylogger download downloads protect protection server servers
static cdn media image images files panel control center family parent parental child children kids backup storage
""".split())


@dataclass(frozen=True)
class NormalizedIndicator:
    kind: str
    value: str

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.value}"


class NormalizationError(ValueError):
    pass


def refang(raw: str) -> str:
    text = raw.strip()
    for pattern, replacement in _REFANG:
        text = pattern.sub(replacement, text)
    return text


def _guard(raw: object) -> str:
    if not isinstance(raw, str):
        raise NormalizationError("value must be text")
    if len(raw) > MAX_VALUE_LEN:
        raise NormalizationError("value too long")
    if _CONTROL.search(raw):
        raise NormalizationError("control characters not allowed")
    text = refang(raw)
    if not text:
        raise NormalizationError("empty value")
    return text


def normalize_domain(raw: str) -> str:
    text = _guard(raw).lower().rstrip(".")
    if text.startswith("*."):
        text = text[2:]
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise NormalizationError("invalid internationalized domain") from exc
    if len(text) > 253 or "." not in text:
        raise NormalizationError("invalid domain")
    labels = text.split(".")
    if not all(_LABEL.match(label) for label in labels):
        raise NormalizationError("invalid domain label")
    if labels[-1].isdigit():
        raise NormalizationError("numeric top-level label")
    return text


def normalize_ip(raw: str) -> tuple[str, str]:
    text = _guard(raw)
    try:
        address = ipaddress.ip_address(text.strip("[]"))
    except ValueError as exc:
        raise NormalizationError("invalid ip address") from exc
    return (KIND_IPV4 if address.version == 4 else KIND_IPV6), address.compressed


def normalize_url(raw: str) -> str:
    text = _guard(raw)
    if "://" not in text:
        text = "http://" + text
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:
        raise NormalizationError("invalid url") from exc
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https", "ftp", "ws", "wss"}:
        raise NormalizationError("unsupported url scheme")
    host = parts.hostname or ""
    try:
        _, host_norm = normalize_ip(host)
        if ":" in host_norm:
            host_norm = f"[{host_norm}]"
    except NormalizationError:
        host_norm = normalize_domain(host)
    default_port = {"http": 80, "https": 443, "ftp": 21, "ws": 80, "wss": 443}[scheme]
    netloc = host_norm if port in (None, default_port) else f"{host_norm}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def normalize_hash(raw: str, kind: str) -> str:
    text = _guard(raw).lower().replace(":", "").replace(" ", "")
    if len(text) != _HASH_LEN[kind] or not _HEX.match(text):
        raise NormalizationError("invalid hash")
    return text


def normalize_app_id(raw: str) -> str:
    text = _guard(raw)
    if len(text) > 255 or not _PACKAGE.match(text):
        raise NormalizationError("invalid android package name")
    return text


def normalize_email(raw: str) -> str:
    text = _guard(raw)
    if not _EMAIL.match(text):
        raise NormalizationError("invalid email")
    local, domain = text.rsplit("@", 1)
    return f"{local}@{normalize_domain(domain)}"


def normalize_freeform(raw: str) -> str:
    text = _guard(raw)
    return text.strip()


def normalize(kind: str, raw: str) -> NormalizedIndicator:
    if kind == KIND_DOMAIN:
        try:
            ip_kind, ip_value = normalize_ip(raw)
            return NormalizedIndicator(ip_kind, ip_value)
        except NormalizationError:
            return NormalizedIndicator(KIND_DOMAIN, normalize_domain(raw))
    if kind == KIND_URL:
        return NormalizedIndicator(KIND_URL, normalize_url(raw))
    if kind in (KIND_IPV4, KIND_IPV6):
        ip_kind, value = normalize_ip(raw)
        return NormalizedIndicator(ip_kind, value)
    if kind in _HASH_LEN:
        return NormalizedIndicator(kind, normalize_hash(raw, kind))
    if kind == KIND_APP:
        return NormalizedIndicator(KIND_APP, normalize_app_id(raw))
    if kind == KIND_EMAIL:
        return NormalizedIndicator(KIND_EMAIL, normalize_email(raw))
    if kind in (KIND_FILE_NAME, KIND_FILE_PATH, KIND_PROCESS, KIND_ANDROID_PROP, KIND_OTHER):
        return NormalizedIndicator(kind, normalize_freeform(raw))
    raise NormalizationError("unknown indicator kind")


_HASH_ALIASES = {
    "sha256": KIND_SHA256, "sha-256": KIND_SHA256, "sha1": KIND_SHA1, "sha-1": KIND_SHA1, "md5": KIND_MD5,
}


def stix_path_to_kind(object_type: str, path: tuple[str, ...]) -> str | None:
    head = path[0].lower() if path else ""
    tail = path[-1].lower().strip("'\"") if path else ""
    if object_type == "domain-name" and head == "value":
        return KIND_DOMAIN
    if object_type == "url" and head == "value":
        return KIND_URL
    if object_type == "ipv4-addr" and head == "value":
        return KIND_IPV4
    if object_type == "ipv6-addr" and head == "value":
        return KIND_IPV6
    if object_type == "email-addr" and head == "value":
        return KIND_EMAIL
    if object_type in ("file", "artifact") and head == "hashes":
        return _HASH_ALIASES.get(tail)
    if object_type == "file" and head == "name":
        return KIND_FILE_NAME
    if object_type == "file" and head == "path":
        return KIND_FILE_PATH
    if object_type == "process" and head == "name":
        return KIND_PROCESS
    if object_type == "app" and head == "id":
        return KIND_APP
    if object_type == "app" and head == "cert":
        return KIND_CERT if tail in ("sha256", "sha-256") else (KIND_CERT_SHA1 if tail in ("sha1", "sha-1") else None)
    if object_type == "x509-certificate" and head == "hashes":
        return KIND_CERT if tail in ("sha256", "sha-256") else (KIND_CERT_SHA1 if tail in ("sha1", "sha-1") else None)
    if object_type == "android-property" and head == "name":
        return KIND_ANDROID_PROP
    if object_type == "software" and head == "x_android_package":
        return KIND_APP
    return None


class SuffixList:
    def __init__(self, rules: set[str] | None = None, wildcards: set[str] | None = None, exceptions: set[str] | None = None):
        self.rules = set(rules or _BUILTIN_SUFFIXES)
        self.wildcards = set(wildcards or ())
        self.exceptions = set(exceptions or ())

    @classmethod
    def from_file(cls, path: Path) -> "SuffixList":
        rules: set[str] = set(_BUILTIN_SUFFIXES)
        wildcards: set[str] = set()
        exceptions: set[str] = set()
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip().split(" ")[0]
                if not line or line.startswith("//"):
                    continue
                try:
                    line = line.encode("idna").decode("ascii").lower()
                except UnicodeError:
                    continue
                if line.startswith("!"):
                    exceptions.add(line[1:])
                elif line.startswith("*."):
                    wildcards.add(line[2:])
                else:
                    rules.add(line)
        return cls(rules, wildcards, exceptions)

    def public_suffix_len(self, labels: list[str]) -> int:
        best = 1
        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in self.exceptions:
                return len(labels) - i - 1
            if candidate in self.rules:
                best = max(best, len(labels) - i)
            if i + 1 < len(labels) and ".".join(labels[i + 1:]) in self.wildcards:
                best = max(best, len(labels) - i)
        return best

    def registered_domain(self, domain: str) -> str | None:
        labels = domain.split(".")
        suffix_len = self.public_suffix_len(labels)
        if suffix_len >= len(labels):
            return None
        return ".".join(labels[-(suffix_len + 1):])


BUNDLED_PSL = Path(__file__).resolve().parent / "data" / "public_suffix_list.dat"
_suffix_list = SuffixList.from_file(BUNDLED_PSL) if BUNDLED_PSL.is_file() else SuffixList()


def load_suffix_list(path: Path) -> bool:
    global _suffix_list
    if path.is_file():
        _suffix_list = SuffixList.from_file(path)
        registered_domain.cache_clear()
        return True
    return False


@lru_cache(maxsize=200_000)
def registered_domain(domain: str) -> str | None:
    return _suffix_list.registered_domain(domain)


def is_shared_infrastructure(root: str | None) -> bool:
    return root is None or root in SHARED_INFRA_ROOTS


def host_of(ind: NormalizedIndicator) -> str | None:
    if ind.kind == KIND_DOMAIN:
        return ind.value
    if ind.kind == KIND_URL:
        host = urlsplit(ind.value).hostname
        return host if host and not _is_ip(host) else None
    if ind.kind == KIND_EMAIL:
        return ind.value.rsplit("@", 1)[1]
    return None


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip("[]"))
        return True
    except ValueError:
        return False


def root_of(ind: NormalizedIndicator) -> str | None:
    host = host_of(ind)
    return registered_domain(host) if host else None


def package_namespace(app_id: str) -> str | None:
    labels = app_id.lower().split(".")
    if len(labels) < 2:
        return None
    namespace = ".".join(labels[:2])
    if namespace in GENERIC_PACKAGE_NAMESPACES or labels[0] in GENERIC_PACKAGE_NAMESPACES:
        return None
    if len(labels[1]) < 4 or labels[1] in _STOP_TOKENS:
        return None
    return namespace


_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def distinctive_tokens(ind: NormalizedIndicator) -> frozenset[str]:
    source: list[str] = []
    if ind.kind in (KIND_DOMAIN, KIND_URL, KIND_EMAIL):
        host = host_of(ind)
        root = registered_domain(host) if host else None
        if root and not is_shared_infrastructure(root):
            source.append(root.split(".")[0])
    elif ind.kind == KIND_APP:
        labels = ind.value.lower().split(".")
        if ".".join(labels[:2]) not in GENERIC_PACKAGE_NAMESPACES:
            source.extend(labels[1:])
    tokens: set[str] = set()
    for chunk in source:
        if len(chunk) >= 5 and chunk not in _STOP_TOKENS and not chunk.isdigit():
            tokens.add(chunk)
        for part in _TOKEN_SPLIT.split(chunk):
            if len(part) >= 5 and part not in _STOP_TOKENS and not part.isdigit():
                tokens.add(part)
    return frozenset(tokens)


_GENERIC_NAME_TOKENS = frozenset("""
spy spyware stalkerware tracker tracking rat trojan sms androidos android ios mobile phone app apps monitor monitoring
for the free pro lite agent a b c d variant family malware backdoor stealer banker loader dropper
""".split())


def core_family_name(norm_name: str) -> str:
    parts = [p for p in re.split(r"[^a-z0-9]+", norm_name.lower()) if p]
    kept: list[str] = []
    for part in parts:
        if part in _GENERIC_NAME_TOKENS:
            continue
        for generic in ("spyware", "spy", "tracker", "monitor"):
            if part.endswith(generic) and len(part) > len(generic):
                part = part[: -len(generic)]
                break
        if part.startswith("spy") and len(part) > 3:
            part = part[3:]
        if part and part not in _GENERIC_NAME_TOKENS:
            kept.append(part)
    return " ".join(kept)


def normalize_family_name(name: str) -> str:
    text = _guard(name).lower()
    text = re.sub(r"[\s_\-./]+", " ", text).strip()
    return text
