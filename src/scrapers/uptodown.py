# ---------------------------------------------------------
# Copyright (C) 2026 krvstek (Original Author)
# Copyright (C) 2026 The uni-apks Contributors (Modifications)
#
# DO NOT REMOVE OR ALTER THIS COPYRIGHT HEADER.
# This file is part of uni-apks.
# Canonical source: https://github.com/krvstek/uni-apks
#
# Licensed under the GNU GPLv3. You may modify this file,
# but you MUST keep this original copyright notice intact
# and prominently state any changes made.
# See the AUTHORS file in the root directory for details.
# ---------------------------------------------------------

import json  # noqa: I001
import re
import zipfile
from pathlib import Path
from typing import Any, override

from src.core.network import NetworkManager
from src.scrapers.base import AppMetadata, BaseScraper, DownloadResult, ScraperError, parse_html


class UptodownError(ScraperError):
    pass


class UptodownScraper(BaseScraper):
    def __init__(self, net: NetworkManager) -> None:
        super().__init__(net)
        self._versions_cache: dict[str, str] = {}

    @override
    def fetch_metadata(self, url: str) -> AppMetadata:
        clean_url = url.rstrip("/").removesuffix("/download").rstrip("/")
        versions_html = self.net.get(f"{clean_url}/versions")
        self._versions_cache[clean_url] = versions_html

        soup_ver = parse_html(versions_html)
        pkg_name = ""

        try:
            dl_page = self.net.get(f"{clean_url}/download")
            soup_dl = parse_html(dl_page)
            th = soup_dl.find("th", string=re.compile(r"Package\s*Name", re.I))
            if th and (td := th.find_next_sibling("td")):
                pkg_name = td.get_text(strip=True)
        except Exception:
            pass

        if not pkg_name:
            try:
                main_html = self.net.get(clean_url)
                soup_main = parse_html(main_html)
                th = soup_main.find("th", string=re.compile(r"Package\s*Name", re.I))
                if th and (td := th.find_next_sibling("td")):
                    pkg_name = td.get_text(strip=True)
            except Exception:
                pass

        if not pkg_name:
            slug = clean_url.partition("//")[2].partition(".")[0]
            pkg_name = "jp.ne.ibis.ibispaintx.app" if "ibispaint" in slug else slug

        versions = [text for el in soup_ver.select(".version") if (text := el.get_text(strip=True))]
        return AppMetadata(pkg_name=pkg_name, versions=versions or ["latest"])

    def _extract_dl_url(self, page_url: str, html: str) -> str | None:
        soup = parse_html(html)
        btn = soup.select_one("#detail-download-button, a.button.download")
        if btn and "download-link-deeplink" in str(btn.get("onclick") or ""):
            html = self.net.get(f"{page_url}-x")
            soup = parse_html(html)
            btn = soup.select_one("#detail-download-button, a.button.download")

        if btn and (data_url := btn.get("data-url")):
            return f"https://dw.uptodown.com/dwn/{data_url}"
        if btn and (href := btn.get("href")):
            return str(href)
        return None

    def _resolve_version_dl_url(self, clean_url: str, version: str) -> str | None:
        versions_html = self._versions_cache.get(clean_url) or self.net.get(f"{clean_url}/versions")
        soup_ver = parse_html(versions_html)
        clean_ver = version.partition("-")[0].lstrip("v")

        for item in soup_ver.select("#versions-items-list div[data-url]"):
            ver_el = item.select_one(".version")
            if ver_el and ver_el.get_text(strip=True) in (version, clean_ver):
                ver_page_url = str(item["data-url"]).rstrip("/")
                return self._extract_dl_url(ver_page_url, self.net.get(ver_page_url))

        h1 = soup_ver.find("h1", id="detail-app-name")
        data_code = str(h1.get("data-code") or "") if h1 else ""
        if not data_code:
            return None

        for page in range(1, 15):
            try:
                raw = self.net.get(f"{clean_url}/apps/{data_code}/versions/{page}")
                version_data: list[dict[str, Any]] = json.loads(raw).get("data", [])
            except Exception:
                break
            if not version_data:
                break
            for entry in version_data:
                if entry.get("version") in (version, clean_ver):
                    parts = entry.get("versionURL") or {}
                    if isinstance(parts, dict) and parts.get("url") and parts.get("versionID"):
                        extra = f"/{parts['extraURL']}" if parts.get("extraURL") else ""
                        ver_page_url = f"{parts['url']}{extra}/{parts['versionID']}"
                        if dl := self._extract_dl_url(ver_page_url, self.net.get(ver_page_url)):
                            return dl
        return None

    @override
    def download(self, url: str, version: str, dest: Path, arch: str, dpi: str, version_code: str | None = None, strict_arch: bool = False) -> DownloadResult:
        clean_url = url.rstrip("/").removesuffix("/download").rstrip("/")
        final_dl_url: str | None = None

        if version and version not in ("auto", "latest", "exp"):
            try:
                final_dl_url = self._resolve_version_dl_url(clean_url, version)
            except Exception:
                final_dl_url = None

        if not final_dl_url:
            dl_page_url = f"{clean_url}/download"
            final_dl_url = self._extract_dl_url(dl_page_url, self.net.get(dl_page_url))

        if not final_dl_url:
            raise UptodownError(f"Could not find download URL on '{clean_url}/download'")

        self.net.download(final_dl_url, dest)
        is_bundle = False
        if zipfile.is_zipfile(dest):
            with zipfile.ZipFile(dest, "r") as zf:
                names = zf.NameToInfo
                if "AndroidManifest.xml" not in names and ("base.apk" in names or any(n.endswith(".apk") for n in names)):
                    is_bundle = True
        if is_bundle:
            apkm_dest = dest.with_suffix(".apkm")
            dest.replace(apkm_dest)
            return DownloadResult(path=apkm_dest, is_bundle=True)
        return DownloadResult(path=dest, is_bundle=False)
