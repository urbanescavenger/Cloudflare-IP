#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把多个 Cloudflare 优选 IP 库合并成一份固定格式的列表。

各家的格式并不统一：

    * 1.2.3.4:443#JP            zip.cm.edu.kg（CM 风格）
    * 1.2.3.4:443#SG 🇸🇬         LancelotRar/best-cf-ips
    * 1.2.3.4:443#HK [高速 13M]  HandsomeMJZ/cfip、svip-s、cf.junzhen
    * 1.2.3.4:443#US-6a98c7      joname1/BestCFip（地区码后挂哈希）
    * 1.2.3.4#CMCC-IPv4_1        DustinWin/BestCF（没有端口）
    * JSON                       HostMonit、VPS789

CFPick 只认 `IP:PORT#CC`，所以这里把所有源都归一化成这一种格式，去重，
再按需只保留 Cloudflare 官方网段内的地址。

输出：
    ip_libs.txt      合并后的全部候选（含非 Cloudflare 的中转 IP）
    ip_libs_cf.txt   只保留 Cloudflare 官方 IPv4 网段（给 CFPick 用）
    ip_libs_stats.json  本次运行统计

仅使用标准库，Actions 里不需要 pip install。
"""

import argparse
import ipaddress
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

USER_AGENT = "cfip-libs/1.0 (+https://github.com/urbanescavenger/Cloudflare-IP)"
DEFAULT_TIMEOUT = 25
DEFAULT_RETRIES = 2

# 数据源：name 用于日志/统计，kind = text | hostmonit | vps789
SOURCES = [
    # ---- 纯文本库 ----
    {"name": "CM(zip.cm.edu.kg)", "kind": "text",
     "url": "https://zip.cm.edu.kg/all.txt"},
    {"name": "LancelotRar top200", "kind": "text",
     "url": "https://raw.githubusercontent.com/LancelotRar/best-cf-ips/main/best-cf-ip-scanned-top200.txt"},
    {"name": "HandsomeMJZ full", "kind": "text",
     "url": "https://raw.githubusercontent.com/HandsomeMJZ/cfip/main/full_ips.txt"},
    {"name": "HandsomeMJZ (mirror)", "kind": "text",
     "url": "https://cf.junzhen.qzz.io/full_ips.txt"},
    {"name": "joname1 BestCFip v4", "kind": "text",
     "url": "https://raw.githubusercontent.com/joname1/BestCFip/main/ipv4.txt"},
    {"name": "DustinWin bestcf", "kind": "text",
     "url": "https://raw.githubusercontent.com/DustinWin/BestCF/bestcf/bestcf-ip.txt"},
    {"name": "DustinWin 移动", "kind": "text",
     "url": "https://raw.githubusercontent.com/DustinWin/BestCF/bestcf/cmcc-ip.txt"},
    {"name": "DustinWin 联通", "kind": "text",
     "url": "https://raw.githubusercontent.com/DustinWin/BestCF/bestcf/cucc-ip.txt"},
    {"name": "DustinWin 电信", "kind": "text",
     "url": "https://raw.githubusercontent.com/DustinWin/BestCF/bestcf/ctcc-ip.txt"},
    {"name": "svip-s (陕西移动)", "kind": "text",
     "url": "https://ips.gaoji.uk/best_ips.txt"},
    {"name": "IPDB bestcf v4", "kind": "text",
     "url": "https://raw.githubusercontent.com/ymyuuu/IPDB/main/BestCF/bestcfv4.txt"},
    {"name": "ipdb.api bestcf", "kind": "text",
     "url": "https://ipdb.api.030101.xyz/?type=bestcf"},
    # ---- JSON 接口 ----
    {"name": "HostMonit", "kind": "hostmonit",
     "url": "https://api.hostmonit.com/get_optimization_ip",
     "body": {"key": "iDetkOys"}},
    {"name": "VPS789", "kind": "vps789",
     "url": "https://vps789.com/openApi/cfIpApi"},
]

CF_RANGES_URL = "https://www.cloudflare.com/ips-v4"

_V4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_REGION = re.compile(r"^([A-Za-z]{2})(?![A-Za-z])")


def _valid_ipv4(text):
    match = _V4.match(text)
    if not match:
        return False
    return all(0 <= int(octet) <= 255 for octet in match.groups())


def _region_code(rest):
    """把 `#` 后面的内容压成两位国家码，认不出就返回空串。

    `SG 🇸🇬`      -> SG
    `HK [高速 13M]` -> HK
    `US-6a98c7`    -> US
    `CMCC-IPv4_1`  -> ""（前两位后面还是字母，不是国家码）
    """
    rest = rest.strip()
    if not rest:
        return ""
    match = _REGION.match(rest)
    return match.group(1).upper() if match else ""


def parse_line(line):
    """把任意库的一行解析成 (ip, port, region)，认不出返回 None。"""
    raw = line.strip().lstrip("﻿")
    if not raw or raw.startswith("#"):
        return None

    head, _, rest = raw.partition("#")
    head = head.strip()

    address = head
    port = 443
    if ":" in head:
        address, _, port_text = head.partition(":")
        if not port_text.isdigit():
            return None
        port = int(port_text)
    # 方括号 IPv6 暂不支持：CFPick 的在线源只处理 IPv4
    if not _valid_ipv4(address):
        return None
    if not 1 <= port <= 65535:
        return None
    return address, port, _region_code(rest)


def parse_text(text):
    entries = []
    for line in text.splitlines():
        parsed = parse_line(line)
        if parsed:
            entries.append(parsed)
    return entries


def parse_hostmonit(payload):
    data = json.loads(payload)
    entries = []
    for item in data.get("info") or []:
        ip = str(item.get("ip") or "").strip()
        if _valid_ipv4(ip):
            # JSON 里没有国家码，统一留空，避免被地区过滤误当成某个国家
            entries.append((ip, 443, ""))
    return entries


def parse_vps789(payload):
    data = json.loads(payload)
    groups = (data.get("data") or {})
    entries = []
    for key in ("CT", "CU", "CM", "AllAvg"):
        for item in groups.get(key) or []:
            ip = str(item.get("ip") or "").strip()
            if _valid_ipv4(ip):
                entries.append((ip, 443, ""))
    return entries


PARSERS = {"hostmonit": parse_hostmonit, "vps789": parse_vps789}

_SSL_CONTEXT = None
_SSL_CHECKED = False


def _ssl_context():
    """系统没有 CA 包时（Windows/conda 常见）退回 certifi。

    Actions 的 Ubuntu runner 有系统 CA，这里返回 None，走默认校验。
    """
    global _SSL_CONTEXT, _SSL_CHECKED
    if _SSL_CHECKED:
        return _SSL_CONTEXT
    _SSL_CHECKED = True
    paths = ssl.get_default_verify_paths()
    if paths.cafile and os.path.exists(paths.cafile):
        return None
    try:
        import certifi
    except ImportError:
        return None
    _SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
    return _SSL_CONTEXT


def fetch(url, timeout, retries, body=None):
    headers = {"User-Agent": USER_AGENT}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    context = _ssl_context()
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            request = urllib.request.Request(url, data=data, headers=headers)
            with urllib.request.urlopen(request, timeout=timeout,
                                        context=context) as response:
                return response.read().decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)
            if attempt < retries:
                time.sleep(2)
    raise RuntimeError(last_error or "unknown error")


def cloudflare_networks(timeout):
    text = fetch(CF_RANGES_URL, timeout, DEFAULT_RETRIES)
    networks = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            networks.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    if not networks:
        raise RuntimeError("Cloudflare 网段解析失败")
    return networks


def sort_key(entry):
    address, port, region = entry
    return (int(ipaddress.IPv4Address(address)), port, region)


def write_list(path, entries):
    # 认不出地区的条目写成 #XX：CFPick 的正则要求 # 后至少一个字母数字，
    # 留空会导致整行被丢掉；XX 也不会命中任何地区筛选。
    lines = ["%s:%d#%s" % (entry[0], entry[1], entry[2] or "XX")
             for entry in entries]
    Path(path).write_text("\n".join(lines) + ("\n" if lines else ""),
                          encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=".", help="输出目录")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("--no-cloudflare-only", action="store_true",
                        help="不做 Cloudflare 网段过滤（同时输出全部候选）")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    seen = set()
    stats = {"updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "sources": [], "total": 0, "cloudflare_total": 0}

    networks = None
    if not args.no_cloudflare_only:
        try:
            networks = cloudflare_networks(args.timeout)
        except RuntimeError as exc:
            print("[!] 无法获取 Cloudflare 网段，保留全部候选: %s" % exc)

    def in_cloudflare(entry):
        if not networks:
            return True
        return any(ipaddress.IPv4Address(entry[0]) in network
                   for network in networks)

    for source in SOURCES:
        name, kind, url = source["name"], source["kind"], source["url"]
        try:
            payload = fetch(url, args.timeout, args.retries, source.get("body"))
            entries = PARSERS[kind](payload) if kind in PARSERS else parse_text(payload)
        except (RuntimeError, ValueError, KeyError, TypeError) as exc:
            print("[-] %-24s 失败: %s" % (name, exc))
            stats["sources"].append({"name": name, "url": url, "count": 0,
                                     "error": str(exc)})
            continue
        added = 0
        for entry in entries:
            if entry not in seen:
                seen.add(entry)
                added += 1
        cf_count = sum(1 for entry in entries if in_cloudflare(entry))
        print("[+] %-24s %5d 条（新增 %d，Cloudflare 网段 %d）"
              % (name, len(entries), added, cf_count))
        stats["sources"].append({"name": name, "url": url,
                                 "count": len(entries), "added": added,
                                 "cloudflare_count": cf_count})

    entries = sorted(seen, key=sort_key)
    write_list(out_dir / "ip_libs.txt", entries)
    stats["total"] = len(entries)

    cf_entries = [entry for entry in entries if in_cloudflare(entry)]
    write_list(out_dir / "ip_libs_cf.txt", cf_entries)
    stats["cloudflare_total"] = len(cf_entries)

    by_port, by_region = {}, {}
    for _, port, region in cf_entries:
        by_port[str(port)] = by_port.get(str(port), 0) + 1
        key = region or "XX"
        by_region[key] = by_region.get(key, 0) + 1
    stats["by_port"] = dict(sorted(by_port.items(), key=lambda kv: -kv[1]))
    stats["by_region"] = dict(sorted(by_region.items(), key=lambda kv: -kv[1]))

    (out_dir / "ip_libs_stats.json").write_text(
        json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print("合并完成: %d 条候选，其中 Cloudflare 网段内 %d 条"
          % (stats["total"], stats["cloudflare_total"]))
    if not entries:
        print("没有拿到任何候选 IP", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
