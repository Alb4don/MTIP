from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

import requests
from taxii2client.common import _HTTPConnection
from taxii2client.exceptions import TAXIIServiceException
from taxii2client.v21 import Collection, Server, as_pages

from ..logging_setup import get_logger
from ..security import InputRejected, validate_outbound_url

log = get_logger("taxii")

MAX_RESPONSE_BYTES = 64 * 1024 * 1024


class TaxiiError(RuntimeError):
    def __init__(self, public_message: str):
        super().__init__(public_message)
        self.public_message = public_message


class GuardedSession(requests.Session):
    def __init__(self, timeout: int, allow_private: bool):
        super().__init__()
        self._timeout = timeout
        self._allow_private = allow_private
        self.max_redirects = 0
        self.trust_env = True

    def request(self, method, url, *args, **kwargs):
        validate_outbound_url(str(url), self._allow_private)
        kwargs["timeout"] = self._timeout
        kwargs["allow_redirects"] = False
        kwargs["stream"] = True
        response = super().request(method, url, *args, **kwargs)
        if 300 <= response.status_code < 400:
            response.close()
            raise TaxiiError("server attempted a redirect; follow-up blocked")
        declared = response.headers.get("Content-Length")
        if declared and declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
            response.close()
            raise TaxiiError("server response is too large")
        body = bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            body.extend(chunk)
            if len(body) > MAX_RESPONSE_BYTES:
                response.close()
                raise TaxiiError("server response is too large")
        response._content = bytes(body)
        response._content_consumed = True
        return response


@dataclass
class CollectionInfo:
    api_root: str
    id: str
    title: str
    can_read: bool
    url: str

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def _connection(timeout: int, allow_private: bool, user: str | None, password: str | None) -> _HTTPConnection:
    conn = _HTTPConnection(user=user, password=password, version="2.1", user_agent="mtip/0.9")
    session = GuardedSession(timeout, allow_private)
    session.verify = True
    if user and password:
        session.auth = requests.auth.HTTPBasicAuth(user, password)
    conn.session = session
    return conn


def _wrap(call: Callable[[], Any]) -> Any:
    try:
        return call()
    except (TaxiiError, InputRejected):
        raise
    except requests.exceptions.SSLError as exc:
        raise TaxiiError("TLS verification failed for the server") from exc
    except requests.exceptions.Timeout as exc:
        raise TaxiiError("server did not respond in time") from exc
    except requests.exceptions.TooManyRedirects as exc:
        raise TaxiiError("server attempted a redirect; follow-up blocked") from exc
    except requests.exceptions.HTTPError as exc:
        status = getattr(exc.response, "status_code", None)
        if status in (401, 403):
            raise TaxiiError("server refused access; check credentials") from exc
        raise TaxiiError("server returned an error") from exc
    except requests.exceptions.RequestException as exc:
        raise TaxiiError("could not reach the server") from exc
    except (TAXIIServiceException, ValueError, KeyError, TypeError) as exc:
        raise TaxiiError("server response is not valid TAXII 2.1") from exc


def discover(url: str, timeout: int, allow_private: bool, user: str | None = None, password: str | None = None) -> list[CollectionInfo]:
    clean = validate_outbound_url(url, allow_private)
    conn = _connection(timeout, allow_private, user, password)

    def run() -> list[CollectionInfo]:
        server = Server(clean, conn=conn)
        found: list[CollectionInfo] = []
        roots = list(server.api_roots)[:20]
        for root in roots:
            for coll in list(root.collections)[:200]:
                found.append(CollectionInfo(root.url, str(coll.id)[:200], str(coll.title or "")[:200], bool(coll.can_read), coll.url))
        return found

    try:
        return _wrap(run)
    finally:
        conn.close()


def fetch_collection(collection_url: str, timeout: int, allow_private: bool, max_pages: int, added_after: str | None = None,
                     user: str | None = None, password: str | None = None) -> bytes:
    clean = validate_outbound_url(collection_url, allow_private)
    conn = _connection(timeout, allow_private, user, password)

    def run() -> bytes:
        collection = Collection(clean, conn=conn)
        if not collection.can_read:
            raise TaxiiError("collection is not readable")
        objects: list[dict[str, Any]] = []
        kwargs: dict[str, Any] = {}
        if added_after:
            kwargs["added_after"] = added_after
        for pages, envelope in enumerate(as_pages(collection.get_objects, per_request=1000, **kwargs)):
            if pages >= max_pages:
                break
            batch = envelope.get("objects", []) if isinstance(envelope, dict) else []
            objects.extend(o for o in batch if isinstance(o, dict))
        return json.dumps({"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000000", "objects": objects}).encode()

    try:
        return _wrap(run)
    finally:
        conn.close()
