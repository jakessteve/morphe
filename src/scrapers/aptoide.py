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

import base64
import json
import re
from pathlib import Path
from typing import Any, override

from src.core.network import NetworkManager
from src.scrapers.base import AppMetadata, BaseScraper, DownloadResult, ScraperError

_BASE_URL: str = "https://ws75.aptoide.com/api/7/"
_PKG_RE: re.Pattern[str] = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")
_CPU_MAP: dict[str, str] = {
    "arm64-v8a": "arm64-v8a,armeabi-v7a,armeabi",
    "armeabi-v7a": "armeabi-v7a,armeabi",
    "x86_64": "x86_64,x86",
    "x86": "x86",
}


class AptoideError(ScraperError):
    pass


def _get_q_param(arch: str, strict_arch: bool = False) -> str:
    if arch in ("all", "both", "universal"):
        return ""
    cpu = arch if strict_arch else _CPU_MAP.get(arch, "")
    if not cpu:
        return ""
    q_str = f"myCPU={cpu}&leanback=0"
    b64 = base64.b64encode(q_str.encode("utf-8")).decode("utf-8")
    return f"&q={b64}"


class AptoideScraper(BaseScraper):
    def __init__(self, net: NetworkManager) -> None:
        super().__init__(net)
        self._pkg_cache: dict[str, str] = {}

    def _resolve_package(self, url_or_pkg: str) -> str:
        clean = url_or_pkg.strip().rstrip("/")
        if clean in self._pkg_cache:
            return self._pkg_cache[clean]

        if _PKG_RE.match(clean) and not clean.endswith((".com", ".org", ".net", ".io")):
            self._pkg_cache[clean] = clean
            return clean

        m_query = re.search(r"package_name=([\w.]+)", clean)
        if m_query:
            pkg = m_query.group(1)
            self._pkg_cache[clean] = pkg
            return pkg

        query = clean.partition("//")[2].partition(".")[0] if "aptoide.com" in clean else clean
        search_url = f"{_BASE_URL}apps/search?query={query}&limit=1&trusted=true"
        data = json.loads(self.net.get(search_url))
        items: list[dict[str, Any]] = data.get("datalist", {}).get("list", [])
        if not items or not items[0].get("package"):
            raise AptoideError(f"Package not found on Aptoide for {url_or_pkg!r}")
        pkg = str(items[0]["package"])
        self._pkg_cache[clean] = pkg
        return pkg

    @override
    def fetch_metadata(self, url: str) -> AppMetadata:
        pkg_name = self._resolve_package(url)
        versions_url = f"{_BASE_URL}listAppVersions?package_name={pkg_name}&limit=50"
        data = json.loads(self.net.get(versions_url))
        items: list[dict[str, Any]] = data.get("datalist", {}).get("list", [])
        versions: list[str] = []
        seen: set[str] = set()
        for app in items:
            ver = str(app.get("file", {}).get("vername") or "").strip()
            if ver and ver not in seen:
                seen.add(ver)
                versions.append(ver)

        if not versions:
            search_url = f"{_BASE_URL}apps/search?query={pkg_name}&limit=1&trusted=true"
            s_data = json.loads(self.net.get(search_url))
            s_items: list[dict[str, Any]] = s_data.get("datalist", {}).get("list", [])
            if s_items:
                ver = str(s_items[0].get("file", {}).get("vername") or "").strip()
                if ver:
                    versions.append(ver)

        if not versions:
            raise AptoideError(f"No versions found on Aptoide for '{pkg_name}'")
        return AppMetadata(pkg_name=pkg_name, versions=versions)

    @override
    def download(self, url: str, version: str, dest: Path, arch: str, dpi: str, version_code: str | None = None, strict_arch: bool = False) -> DownloadResult:
        pkg_name = self._resolve_package(url)
        q = _get_q_param(arch, strict_arch=strict_arch)
        clean_ver = version.partition("-")[0].lstrip("v")

        dl_path: str = ""
        if version.lower() in ("latest", "auto", "exp"):
            search_url = f"{_BASE_URL}apps/search?query={pkg_name}&limit=1&trusted=true{q}"
            res = json.loads(self.net.get(search_url))
            items: list[dict[str, Any]] = res.get("datalist", {}).get("list", [])
            if not items:
                raise AptoideError(f"No app found on Aptoide for '{pkg_name}'")
            dl_path = str(items[0].get("file", {}).get("path") or "")
        else:
            versions_url = f"{_BASE_URL}listAppVersions?package_name={pkg_name}&limit=50{q}"
            res_v = json.loads(self.net.get(versions_url))
            items_v: list[dict[str, Any]] = res_v.get("datalist", {}).get("list", [])
            vercode = None
            for app in items_v:
                file_info = app.get("file", {})
                vname = str(file_info.get("vername") or "").strip()
                vcode_str = str(file_info.get("vercode") or "").strip()
                if (version_code and vcode_str == version_code) or vname in (version, clean_ver):
                    vercode = file_info.get("vercode")
                    if file_info.get("path"):
                        dl_path = str(file_info["path"])
                    break

            if vercode is None:
                raise AptoideError(f"Version '{version}' not found on Aptoide for '{pkg_name}'")

            if not dl_path:
                meta_url = f"{_BASE_URL}getAppMeta?package_name={pkg_name}&vercode={vercode}{q}"
                res_meta = json.loads(self.net.get(meta_url))
                dl_path = str(res_meta.get("data", {}).get("file", {}).get("path") or "")

        if not dl_path:
            raise AptoideError(f"Download path missing on Aptoide for '{pkg_name}' @ '{version}'")

        self.net.download(dl_path, dest)
        return DownloadResult(path=dest, is_bundle=False)
