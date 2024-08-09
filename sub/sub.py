#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import json
import logging
import os
import sys
import tempfile
import time
import traceback
from urllib.parse import urlsplit

import utils
import yaml
from clients import Clash, Mihomo, SingBox, Surge
from flask import Flask, Response, request
from protocols import Hysteria2, Shadowsocks, Trojan, XRay
from werkzeug.exceptions import HTTPException

LOG_FORMAT = "%(asctime)s %(levelname)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger()
_tmpdir = tempfile.gettempdir()
parser = argparse.ArgumentParser(description="简易订阅转换器")
parser.add_argument("-v", action="version", version="%(prog)s version : v0.02", help="显示版本")
parser.add_argument("-url", dest="url", help="订单的原始URL 多个以|分开")
parser.add_argument("-t", "--target", dest="target")
parser.add_argument("-p", dest="port", type=int, default=8080)
parser.add_argument("-web", action="store_true", help="以WEB方式启动，默认端口：8080")
app = Flask(__name__)


def jsonify(body, mimetype="application/json", status=200, headers=None):
    response = body
    if isinstance(body, (list, dict)):
        response = json.dumps(body, ensure_ascii=False)
    return Response(response, mimetype=mimetype, status=status, headers=headers)


def parse_subscribe(content, target=None):
    """
    解析订阅文件内容
    """
    recs = []
    trojan_scheme = ["trojan", "trojan-go"]
    if target is None:
        nodes = utils.b64decode(content).split("\n")
        for node in nodes:
            o = urlsplit(node)
            if o.scheme == "vmess":
                rec = XRay.parse_url(node)
                recs.append(rec)
            elif o.scheme == "vless":
                rec = XRay.parse_url(node)
                recs.append(rec)
            elif o.scheme == "ss":
                rec = Shadowsocks.parse_url(node)
                recs.append(rec)
            elif o.scheme == "hysteria2":
                rec = Hysteria2.parse_url(node)
                recs.append(rec)
            elif o.scheme in trojan_scheme:
                rec = Trojan.parse_url(node)
                recs.append(rec)
    elif target == "clash":
        subinfos = yaml.load(content, Loader=yaml.FullLoader)
        for node in subinfos["proxies"]:
            if node["type"] == "vmess":
                rec = XRay.parse_url(node)
                recs.append(rec)
            elif node["type"] == "ss":
                rec = Shadowsocks.parse_url(node)
                recs.append(rec)
            elif node["type"] == "trojan":
                rec = Trojan.parse_url(node)
                recs.append(rec)
    return recs


def get_subscribe(url):
    """
    从源网站获取订阅数据
    """
    result = utils.get(url)
    if not result.get("content"):
        return None

    result["urlinfo"] = urlsplit(url)
    result["content"] = parse_subscribe(result["content"])
    if not result["content"]:
        return None
    return result


def subconvert(url: str, urls: list, target: str = None, fixed_node: str = None) -> dict:
    ctime = time.strftime("%Y%m%d%H%M", time.localtime())
    filename = f"{url}.{target}"
    filename = f"{utils.md5(filename)}_{ctime}.json"
    filepath = os.path.join(_tmpdir, filename)
    # 从缓存中获取订阅数据
    if os.path.exists(filepath):
        with open(filepath, "rt", encoding="utf-8") as f:
            buff = f.read()
            if len(buff) > 0:
                return json.loads(buff)

    errs = []
    nodes = []
    for url in urls:
        try:
            subscribe = get_subscribe(url)
            if subscribe:
                nodes.append(subscribe)
        except Exception as e:
            errs.append(str(e))

    if not nodes and errs:
        return "\n".join(errs), 500

    params = {
        "url": url,
        "fixed_node": fixed_node,
    }
    result = {}
    if target == "clash.meta":
        clashMeta = Mihomo()
        result = clashMeta.convert(params, nodes)
    if target == "clash":
        clash = Clash()
        result = clash.convert(params, nodes)
    elif target == "surge":
        surge = Surge()
        result = surge.convert(params, nodes)
    elif target == "singbox":
        singbox = SingBox()
        result = singbox.convert(params, nodes)

    # 将原订阅数据保存到缓存
    with open(filepath, "wt", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False))
    return result


@app.errorhandler(Exception)
def handle_error(e):
    code = 500
    if isinstance(e, HTTPException):
        code = e.code
    traceback.print_exc()
    return jsonify({"status": code, "msg": str(e)}, status=500)


@app.route("/", methods=["GET"])
def hello():
    return "hello!", 200


@app.get("/subip")
def get_subip():
    subInfos = []
    for url in request.args.getlist("url"):
        nodes = get_subscribe(url)
        subInfos.extend(nodes["content"])
    urls = [sub.address for sub in subInfos]
    content = utils.parse_base_serverip(urls)
    result = []
    for k, v in content.items():
        result.append(f"{k.upper()}:")
        result.extend(sorted(v))
        result.append("")
    return "\n".join(result), 200, {"Content-Type": "text/plain;charset=UTF-8"}


@app.get("/rosip")
def firewall_subip():
    name = request.args.get("name", "vps")
    subInfos = []
    for url in request.args.getlist("url"):
        try:
            nodes = get_subscribe(url)
            subInfos.extend(nodes["content"])
        except Exception:
            pass
    urls = [sub.address for sub in subInfos]
    content = utils.parse_base_serverip(urls)
    ips = set(content["ip"]) | set(content["server_ips"])
    result = [f'/log info "Loading {name} ipv4 address list"']
    result.append(f"/ip firewall address-list remove [/ip firewall address-list find list={name}]")
    result.append("/ip firewall address-list")
    for ip in sorted(list(ips)):
        result.append(f":do {{ add address={ip}/32 list={name} }} on-error={{}}")
    result.append("")
    return "\n".join(result), 200, {"Content-Type": "text/plain;charset=UTF-8"}


def get_sub_respone(subinfo):
    if subinfo["mimetype"] == "application/yaml":
        sub_body = yaml.safe_dump(subinfo["body"], allow_unicode=True, sort_keys=False, default_flow_style=False)
        return jsonify(sub_body, mimetype=subinfo["mimetype"], headers=subinfo["headers"])
    elif subinfo["mimetype"] == "application/json":
        sub_body = json.dumps(subinfo["body"], ensure_ascii=False, indent=2)
        return jsonify(sub_body, mimetype=subinfo["mimetype"])
    return jsonify(subinfo["body"], mimetype=subinfo["mimetype"])


@app.route("/convert", methods=["GET"])
def convert():
    target = request.args.get("flag", "clash")
    url = request.url
    urls = request.args.getlist("url")
    fixed_node = request.args.get("fixed_node")
    subinfo = subconvert(url, urls, target, fixed_node)
    return get_sub_respone(subinfo)


@app.route("/sub", methods=["GET"])
def sub():
    target = request.args.get("target", "clash")
    url = request.url
    urls = list(map(str.strip, request.args["url"].split("|")))
    fixed_node = request.args.get("fixed_node")
    subinfo = subconvert(url, urls, target, fixed_node)
    return get_sub_respone(subinfo)


def shell_crash_config(crash_dir, sub_urls=[]):
    target = "singbox"
    user_config = ""
    sub_config = ""
    crash_config = f"{crash_dir}/configs/ShellCrash.cfg"
    url = ""
    crashcore = ""
    with open(crash_config, "rt", encoding="utf-8") as f:
        lines = f.readlines()
        for line in lines:
            if not sub_urls and line.startswith("Url="):
                url = line[4:].replace("'", "").strip()
            if line.startswith("crashcore="):
                crashcore = line[10:].strip()

    # 检查订阅链接
    if sub_urls:
        print(f"使用参数传入的订阅URL")
    elif url:
        sub_urls = list(map(str.strip, url.split("|")))
        print(f"使用配置文件中的订阅URL：{url}")
    else:
        input_url = input("配置中没有订阅地址，请输入（多个以 | 分隔）：")
        if not input_url or not input_url.startswith("http"):
            print("无效的订阅URL")
            return
        sub_urls = list(map(str.strip, input_url.split("|")))

    # 检查订阅输出格式
    if not crashcore:
        targets = ["singbox", "clash", "meta"]
        crashcore = input("订阅输出格式{}，[singbox]：".format(", ".join(targets)))
        if not crashcore:
            crashcore = "singbox"
        if crashcore not in targets:
            print("订阅输出格式必须是{}其中之一".format(", ".join(targets)))
            return

    if crashcore in ("singboxp", "singbox"):
        sub_config = f"{crash_dir}/jsons/config.json"
        user_config = f"{crash_dir}/jsons/dns.json"
        target = "singbox"
    elif crashcore in ("clashpre", "meta"):
        sub_config = f"{crash_dir}/yamls/config.yaml"
        user_config = f"{crash_dir}/yamls/user.yaml"
        target = "clash.meta"
    elif crashcore == "clash":
        sub_config = f"{crash_dir}/yamls/config.yaml"
        user_config = f"{crash_dir}/yamls/user.yaml"
        target = "clash"

    if not sub_urls:
        print("没有找到有效的订阅地址，请使用sub -url http://xxx.xx/1 的方式来调用，多个订阅地址用|分隔进行合并")
        return
    if not sub_config:
        print("请先正确安装ShellCrash.")
        return
    if not os.path.exists(os.path.dirname(sub_config)):
        os.mkdir(os.path.dirname(sub_config))

    sub_url = "|".join(sub_urls)
    subinfo = subconvert(sub_url, sub_urls, target=target)
    sub_body = subinfo["body"]
    sub_dns = sub_body.get("dns")

    if subinfo["mimetype"] == "application/yaml":
        if sub_dns:
            sub_dns = {"dns": sub_dns}
            sub_dns = yaml.safe_dump(sub_dns, allow_unicode=True, sort_keys=False, default_flow_style=False)
        sub_body = yaml.safe_dump(sub_body, allow_unicode=True, sort_keys=False, default_flow_style=False)
    elif subinfo["mimetype"] == "application/json":
        if sub_dns:
            sub_dns = {"dns": sub_dns}
            sub_dns = json.dumps(sub_dns, ensure_ascii=False, indent=2)
        sub_body = json.dumps(sub_body, ensure_ascii=False, indent=2)
    with open(sub_config, "wt", encoding="utf-8") as f:
        print(f"已写入订阅配置: {sub_config}")
        f.write(sub_body)

    if sub_dns and not os.path.exists(user_config):
        with open(user_config, "wt", encoding="utf-8") as f:
            f.write(sub_dns)
            print(f"已写入dns配置: {user_config}")


if __name__ == "__main__":
    args = parser.parse_args()
    if args.web:
        app.run("0.0.0.0", args.port)
        sys.exit(0)
    cdir = os.path.dirname(os.path.abspath(__file__))
    crash_dir = os.getenv("CRASHDIR")
    crash_config = f"{crash_dir}/configs/ShellCrash.cfg"
    if not os.path.exists(crash_config):
        crash_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        crash_config = f"{crash_dir}/configs/ShellCrash.cfg"
        if not os.path.exists(crash_config):
            crash_dir = os.getcwd()
            crash_config = f"{crash_dir}/configs/ShellCrash.cfg"

    if os.path.exists(crash_config):
        print(f"找到ShellCrash配置文件: {crash_config}")
        sub_urls = []
        if args.url:
            print("订阅URL：{}".format(args.url))
            sub_urls = list(map(str.strip, args.url.split("|")))
        shell_crash_config(crash_dir, sub_urls=sub_urls)
        sys.exit(0)

    input_url = ""
    if args.url:
        print("订阅URL：{}".format(args.url))
        sub_urls = list(map(str.strip, args.url.split("|")))
        input_url = args.url
    else:
        input_url = input("请输入订阅URL，多个以 | 分隔：")
        if not input_url or not input_url.startswith("http"):
            print("无效的订阅URL")
            sys.exit(0)
        sub_urls = list(map(str.strip, input_url.split("|")))

    targets = ["singbox", "clash", "clash.meta", "surge"]
    if args.target:
        target = args.target
    else:
        target = input("订阅输出格式{}，[singbox]：".format(", ".join(targets)))
        if not target:
            target = "singbox"
    if target not in targets:
        print("订阅输出格式必须是{}其中之一".format(", ".join(targets)))
        sys.exit(0)

    subinfo = subconvert(input_url, sub_urls, target=target)
    if not subinfo or not isinstance(subinfo, dict):
        print("订阅转换失败。")
        sys.exit(0)

    sub_body = subinfo["body"]
    if subinfo["mimetype"] == "application/yaml":
        sub_body = yaml.safe_dump(sub_body, allow_unicode=True, sort_keys=False, default_flow_style=False)
        sub_config = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "config.yaml")
    elif subinfo["mimetype"] == "application/json":
        sub_body = json.dumps(sub_body, ensure_ascii=False, indent=2)
        sub_config = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "config.json")
    elif subinfo["mimetype"] == "text/plain":
        sub_config = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "config.conf")

    with open(sub_config, "wt", encoding="utf-8") as f:
        print(f"已写入订阅配置: {sub_config}")
        f.write(sub_body)
