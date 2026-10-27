from __future__ import annotations

import argparse
import json
import socket
import sys
from dataclasses import replace
from pathlib import Path

from . import __version__
from .config import Settings
from .logging_setup import configure_logging


def _free_port(preferred: int) -> int:
    for port in (preferred, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return sock.getsockname()[1]
            except OSError:
                continue
    raise RuntimeError("no free local port")


def _serve(settings: Settings, open_browser: bool) -> int:
    import threading
    import webbrowser

    import uvicorn

    from .api.app import create_app

    app = create_app(settings)
    url = f"http://127.0.0.1:{settings.port}/"
    print(f"MTIP {__version__} listening on {url}", flush=True)
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="warning", server_header=False,
                proxy_headers=False, timeout_graceful_shutdown=10, access_log=False)
    return 0


def _desktop(settings: Settings) -> int:
    try:
        from .desktop import run_desktop
    except ImportError:
        print("PySide6 with QtWebEngine is not installed; opening the browser interface instead.", file=sys.stderr)
        return _serve(settings, open_browser=True)
    return run_desktop(settings)


def _import(settings: Settings, path: Path, source: str) -> int:
    from .api.schemas import check_source_name
    from .service import Platform

    platform = Platform(settings)
    try:
        name = check_source_name(source)
        data = path.read_bytes()
        if len(data) > settings.max_upload_bytes:
            print("file is larger than the configured limit", file=sys.stderr)
            return 2
        report = platform.importer.import_bytes(data, name)
        print(json.dumps(report.as_dict(), indent=2))
        return 0
    finally:
        platform.close()


def _correlate(settings: Settings, evaluate: bool) -> int:
    from .service import Platform

    platform = Platform(settings)
    try:
        result = platform.engine.run(evaluate=evaluate)
        if result is None:
            print("a correlation run is already in progress", file=sys.stderr)
            return 1
        print(json.dumps(result.stats, indent=2, default=str))
        return 0
    finally:
        platform.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mtip", description="Mobile Threat Intelligence Correlation Platform")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--data-dir", type=Path, help="override the data directory")
    sub = parser.add_subparsers(dest="command")
    serve = sub.add_parser("serve", help="run the web interface on 127.0.0.1")
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--no-browser", action="store_true")
    desk = sub.add_parser("desktop", help="run the desktop window (PySide6)")
    desk.add_argument("--port", type=int, default=None)
    imp = sub.add_parser("import", help="import a STIX bundle from disk")
    imp.add_argument("path", type=Path)
    imp.add_argument("--source", required=True)
    cor = sub.add_parser("correlate", help="run correlation and print statistics")
    cor.add_argument("--no-eval", action="store_true")
    sub.add_parser("migrate", help="apply database migrations (with backup) and exit")
    args = parser.parse_args(argv)

    settings = Settings()
    if args.data_dir:
        settings = replace(settings, data_dir=args.data_dir.expanduser().resolve())
    port = getattr(args, "port", None)
    if args.command in (None, "serve", "desktop"):
        chosen = port if port else settings.port
        if not 1024 <= chosen <= 65535:
            parser.error("port must be between 1024 and 65535")
        settings = replace(settings, port=_free_port(chosen))
    settings.ensure_dirs()
    configure_logging(settings.log_dir)

    try:
        if args.command in (None, "desktop"):
            return _desktop(settings)
        if args.command == "serve":
            return _serve(settings, open_browser=not args.no_browser)
        if args.command == "import":
            return _import(settings, args.path, args.source)
        if args.command == "correlate":
            return _correlate(settings, evaluate=not args.no_eval)
        if args.command == "migrate":
            from .storage import Storage
            storage = Storage(settings.db_path)
            version = storage.migrate(settings.backup_dir)
            storage.close()
            print(f"schema version {version}")
            return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        from .security import InputRejected
        if isinstance(exc, InputRejected):
            print(exc.public_message, file=sys.stderr)
            return 2
        print(f"error: {type(exc).__name__}; see {settings.log_dir}", file=sys.stderr)
        import logging
        logging.getLogger("mtip.cli").error("cli failure type=%s", type(exc).__name__)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
