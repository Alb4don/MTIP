from __future__ import annotations

import sys
import threading
import time
import urllib.request
from pathlib import Path

import uvicorn
from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import QApplication, QFileDialog, QMainWindow, QMessageBox

from . import __version__
from .api.app import create_app
from .config import Settings


class _LocalOnlyPage(QWebEnginePage):
    def __init__(self, origin: str, profile: QWebEngineProfile, parent=None):
        super().__init__(profile, parent)
        self._origin = origin

    def acceptNavigationRequest(self, url: QUrl, nav_type, is_main_frame: bool) -> bool:
        if url.toString().startswith(self._origin):
            return True
        if url.scheme() in ("http", "https"):
            QDesktopServices.openUrl(url)
        return False


class _Server(threading.Thread):
    def __init__(self, settings: Settings):
        super().__init__(daemon=True, name="mtip-server")
        config = uvicorn.Config(create_app(settings), host=settings.host, port=settings.port, log_level="warning",
                                server_header=False, access_log=False, timeout_graceful_shutdown=5)
        self.server = uvicorn.Server(config)

    def run(self) -> None:
        self.server.run()

    def stop(self) -> None:
        self.server.should_exit = True


def _wait_ready(url: str, timeout: float = 20.0) -> bool:
    if not url.startswith("http://127.0.0.1:"):
        return False
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url + "api/v1/health", timeout=1) as response:
                if response.status == 200:
                    return True
        except OSError:
            time.sleep(0.15)
    return False


def run_desktop(settings: Settings) -> int:
    server = _Server(settings)
    server.start()
    origin = f"http://127.0.0.1:{settings.port}/"
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("MTIP")
    if not _wait_ready(origin):
        QMessageBox.critical(None, "MTIP", "The local service did not start. Check the log folder in the data directory.")
        server.stop()
        return 1
    window = QMainWindow()
    window.setWindowTitle(f"Mobile Threat Correlation {__version__}")
    profile = QWebEngineProfile(window)
    profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.NoCache)
    profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies)

    def on_download(item) -> None:
        if not item.url().toString().startswith(origin):
            item.cancel()
            return
        target, _ = QFileDialog.getSaveFileName(window, "Save report", item.downloadFileName())
        if not target:
            item.cancel()
            return
        item.setDownloadDirectory(str(Path(target).parent))
        item.setDownloadFileName(Path(target).name)
        item.accept()

    profile.downloadRequested.connect(on_download)
    view = QWebEngineView(window)
    view.setPage(_LocalOnlyPage(origin, profile, view))
    view.setUrl(QUrl(origin))
    window.setCentralWidget(view)
    window.resize(1400, 900)
    window.show()
    code = app.exec()
    server.stop()
    server.join(timeout=10)
    return int(code)
