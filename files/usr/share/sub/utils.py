# -*- coding:utf-8 -*-

import asyncio
import base64
import datetime
import hashlib
import json
import logging
import os
import re
import socket
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

import requests

_tmpdir = tempfile.gettempdir()
logger = logging.getLogger()
executor = ThreadPoolExecutor(max_workers=5)


async def run(loop, origin_func, *args, **kwargs):
    def _wrapper():
        return origin_func(*args, **kwargs)

    return await loop.run_in_executor(executor, _wrapper)


def _get(url, **kwargs):
    kwargs.setdefault(
        "headers",
        {"User-Agent": "Mozilla/5.0 (iPad; CPU OS 11_0 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko)"},
    )
    return requests.get(url, **kwargs)


def check_ip(ipAddr):
    if not ipAddr:
        return False
    pattern = r"^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$"
    compile_ip = re.compile(pattern)
    return compile_ip.match(ipAddr)


def getaddrinfo(domain):
    ip = set()
    try:
        addinfo = socket.getaddrinfo(domain, None)
        for res in addinfo:
            ip.add(res[4][0])
        return ip
    except Exception:
        logger.error(f"not get addr info {domain}")
    return ip


def batch_get_address_info(domains):
    try:
        loop = asyncio.get_event_loop()
    except Exception:
        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        loop = asyncio.get_event_loop()

    tasks = []
    tasks = [asyncio.ensure_future(run(loop, getaddrinfo, domain)) for domain in domains]
    loop.run_until_complete(asyncio.gather(*tasks))
    addrinfos = [task.result() for task in tasks]
    result = set()
    for info in addrinfos:
        result = result | info
    return result


def parse_base_serverip(urls):
    svrips = set()
    for url in urls:
        if check_ip(url):
            svrips.add(url)
    servers = set(urls) - svrips
    domains = set()
    fail_domains = set()
    for server in servers:
        if server.find(".") < 0:
            fail_domains.add(server)
            continue
        domains.add(".".join(server.split(".")[1:]))
    ips = batch_get_address_info(servers)
    result = {
        "ip": list(ips),
        "server_ips": list(svrips),
        "servers": list(servers - fail_domains),
        "domain": list(domains),
    }
    return result


def b64decode(text) -> str:
    if isinstance(text, str):
        encode_bytes = text.encode()
    elif isinstance(text, bytes):
        encode_bytes = text
    add = 4 - (len(encode_bytes) % 4)
    if add:
        encode_bytes += b"=" * add
    return base64.b64decode(encode_bytes).decode("utf-8")


def md5(s):
    if isinstance(s, bytes):
        b = s
    elif isinstance(s, str):
        b = s.encode("utf-8")
    else:
        b = json.dumps(s, ensure_ascii=False).encode("utf-8")
    return hashlib.md5(b).hexdigest()


def get(url):
    ctime = time.strftime("%Y%m%d%H", time.localtime())
    filename = f"{md5(url)}_{ctime}.json"
    filepath = os.path.join(_tmpdir, filename)
    # 从缓存中获取订阅数据
    if os.path.exists(filepath):
        with open(filepath, "rt", encoding="utf-8") as f:
            buff = f.read()
            if len(buff) > 0:
                return json.loads(buff)

    encoding = "utf-8"

    logger.info(f"GET {url}")
    err = f"不能访问 {url}"
    try:
        response = _get(url, timeout=5)
    except Exception:
        logger.info(err)
        return
    if not response.ok:
        logger.info(err)
        return

    if response.encoding and response.encoding != "ISO-8859-1":
        encoding = response.encoding
    elif response.apparent_encoding and response.apparent_encoding != "ISO-8859-1":
        encoding = response.apparent_encoding

    header_keys = "content-disposition subscription-userinfo profile-update-interval profile-web-page-url".split()
    headers = {k.lower(): v for k, v in response.headers.items() if k in header_keys}
    result = {
        "url": url,
        "headers": headers,
        "content": response.content.decode(encoding, "ignore"),
    }
    if "subscription-userinfo" in headers:
        subscriptionUserinfo = headers["subscription-userinfo"]
        userinfo = {}
        for items in list(map(str.strip, subscriptionUserinfo.split(";"))):
            item = list(map(str.strip, items.split("=")))
            userinfo[item[0]] = int(item[1])

        userinfo["upload"] = round(userinfo.get("upload", 0) / 1073741824, 2)
        userinfo["download"] = round(userinfo.get("download", 0) / 1073741824, 2)
        userinfo["total"] = round(userinfo.get("total", 0) / 1073741824, 2)
        userinfo["balance"] = round(userinfo["total"] - userinfo["upload"] - userinfo["download"], 2)
        dt = datetime.datetime.fromtimestamp(userinfo.get("expire", 0))
        userinfo["expire"] = dt.strftime("%Y-%m-%d %H:%M:%S")
        result["userinfo"] = userinfo

    # 将原订阅数据保存到缓存
    with open(filepath, "wt", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False))

    return result


def download_rule(url, filepath):
    """
    下载规则文件
    """
    filename = os.path.basename(url)
    filepath = os.path.join(filepath, filename)
    if os.path.exists(filepath):
        return filepath
    result = get(url)
    if result:
        with open(filepath, "wt", encoding="utf-8") as f:
            f.write(result["content"])
        return filepath
    return None


def get_rule(hosts):
    result = {}
    if not hosts:
        return result
    try:
        loop = asyncio.get_event_loop()
    except Exception:
        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        loop = asyncio.get_event_loop()
    tasks = []

    ctime = time.strftime("%Y%m%d", time.localtime())
    cwd = "{}/{}".format(_tmpdir, ctime)
    if not os.path.exists(cwd):
        os.mkdir(cwd)
    tasks = [asyncio.ensure_future(run(loop, download_rule, url, cwd)) for url in hosts]
    loop.run_until_complete(asyncio.gather(*tasks))
    files = [task.result() for task in tasks]
    for filepath in files:
        if not filepath or not os.path.exists(filepath):
            continue
        # 从下载的文件中读取配置项
        with open(filepath, "rt", encoding="utf-8") as f:
            lines = f.readlines()
            if lines:
                filename = os.path.basename(filepath)
                result[filename] = lines
    return result
