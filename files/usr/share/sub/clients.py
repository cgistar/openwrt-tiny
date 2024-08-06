# -*- coding: utf-8 -*-


import collections
import configparser
import json
import logging
import os
import re
import sys
from urllib.parse import parse_qsl, quote, unquote, urlsplit, urlunsplit

import utils
import yaml

logger = logging.getLogger()


def ordered_yaml_load(stream, Loader=yaml.SafeLoader, object_pairs_hook=collections.OrderedDict):
    class OrderedLoader(Loader):
        pass

    def _construct_mapping(loader, node):
        loader.flatten_mapping(node)
        return object_pairs_hook(loader.construct_pairs(node))

    OrderedLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)
    return yaml.load(stream, OrderedLoader)


def ordered_yaml_dump(data, stream=None, Dumper=yaml.SafeDumper, object_pairs_hook=collections.OrderedDict, **kwds):
    class OrderedDumper(Dumper):
        pass

    def _dict_representer(dumper, data):
        return dumper.represent_mapping(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, data.items())

    OrderedDumper.add_representer(object_pairs_hook, _dict_representer)
    return yaml.dump(data, stream, OrderedDumper, **kwds)


class SingBox:
    def __init__(self) -> None:
        config_file = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "config.json")
        self.test_url = "http://www.gstatic.com/generate_204"
        self.test_interval = 43200
        self._headers = {}
        with open(config_file, "rt", encoding="utf-8") as f:
            self.config = json.load(f)
            self.countrys = {}
            for name, tags in self.config["countrys"].items():
                if isinstance(tags, str):
                    self.countrys[tags] = name
                if isinstance(tags, list):
                    for tag in tags:
                        self.countrys[tag] = name
            if self.config.get("proxy-test-url"):
                self.test_url = self.config["proxy-test-url"]
            if self.config.get("test-interval"):
                self.test_interval = self.config["test-interval"]

    def init_headers(self, subscribe):
        if self._headers:
            return

        self._headers = subscribe["headers"]

    def format_rule(self, lines: list, sort=True) -> dict:
        """
        对rule数据进行拼装
        """
        result = {
            "domain": set(),
            "domain_suffix": set(),
            "domain_keyword": set(),
            "domain_regex": set(),
            "ip_cidr": set(),
            "process_name": set(),
        }
        new_lines = []
        if sort:
            new_lines = sorted(list(set(lines)))
        else:
            unique_check = set()
            for line in lines:
                if line in unique_check:
                    continue
                unique_check.add(line)
                new_lines.append(line)
        for line in new_lines:
            if not line:
                continue
            s = line.strip()
            if s.startswith("DOMAIN-SUFFIX"):
                rule = list(map(str.strip, s.split(",")))
                result["domain_suffix"].add(rule[1])
            elif s.startswith("DOMAIN-KEYWORD"):
                rule = list(map(str.strip, s.split(",")))
                result["domain_keyword"].add(rule[1])
            elif s.startswith("DOMAIN-REGEX"):
                rule = list(map(str.strip, s.split(",")))
                result["domain_regex"].add(rule[1])
            elif s.startswith("DOMAIN"):
                rule = list(map(str.strip, s.split(",")))
                result["domain"].add(rule[1])
            elif s.startswith("PROCESS-NAME"):
                rule = list(map(str.strip, s.split(",")))
                result["process_name"].add(rule[1])
            elif s.startswith("IP-CIDR") or s.startswith("IP-CIDR6"):
                rule = list(map(str.strip, s.split(",")))
                result["ip_cidr"].add(rule[1])
        keys = "domain domain_suffix domain_keyword domain_regex ip_cidr process_name"
        return {x: list(result[x]) for x in keys.split() if result.get(x)}

    def _proxy_groups(self, proxies):
        """
        代理组
        """
        groups = collections.defaultdict(list)
        nodeNames = [x.name for x in proxies]

        addNodes = set()
        for p in nodeNames:
            upp = p.upper()
            if upp.find("TEST") >= 0 or p.find("测试") >= 0:
                addNodes.add(p)
                groups["测试线路"].append(p)
            elif upp.find("VIP") >= 0:
                addNodes.add(p)
                groups["VIP专线"].append(p)
            elif upp.find("IPLC") >= 0:
                addNodes.add(p)
                groups["IPLC专线"].append(p)
            elif upp.find("IEPL") >= 0:
                addNodes.add(p)
                groups["IPLC专线"].append(p)
            elif upp.find("VPS") >= 0:
                addNodes.add(p)
                groups["VPS组"].append(p)
        n = set(nodeNames) - addNodes
        nodeNames = [x for x in nodeNames if x in n]

        # 收集各国专线
        youhui_pattern = re.compile(r"0\.\d+?")
        duobei_pattern = re.compile(r"[x][2-9]|[x][1-9]\d+?|[2-9][xX]|[1-9]\d+?[xX]")
        for name, flag in self.countrys.items():
            addNodes = set()
            for p in nodeNames:
                if p.find(name) >= 0:
                    addNodes.add(p)
                    if youhui_pattern.search(p):
                        groups["优惠线路"].append(p)
                    elif duobei_pattern.search(p):
                        groups["多倍扣费"].append(p)
                    elif p.find("倍") >= 0:
                        groups["多倍扣费"].append(p)
                    else:
                        groups[flag].append(p)
            n = set(nodeNames) - addNodes
            nodeNames = [x for x in nodeNames if x in n]

        # 剩余解析不了的，全部归入其它
        groups["其它"] = list(nodeNames)

        proxy_node = []  # 所有代理节点
        auto_node = []  # 汇入自动选择的节点
        fee_node = []  # 多倍付费节点
        proxyGroups = []

        for item in groups.keys():
            g = {}
            groups_item = sorted(groups[item])
            if item == "多倍扣费":
                g = {"tag": f"💵{item}", "type": "selector", "outbounds": groups_item}
                fee_node.append(g["tag"])
            elif item == "优惠线路":
                g = {"tag": f"🎠{item}", "type": "selector", "outbounds": groups_item}
                auto_node.append(g["tag"])
            elif item == "测试线路":
                g = {"tag": "🪲测试组", "type": "selector", "outbounds": groups_item}
                auto_node.append(g["tag"])
            elif item == "VIP专线":
                g = {"tag": f"👑{item}", "type": "selector", "outbounds": groups_item}
                auto_node.append(g["tag"])
            elif item == "IPLC专线":
                g = {"tag": f"🎉{item}", "type": "selector", "outbounds": groups_item}
                auto_node.append(g["tag"])
            elif item == "IEPL线路":
                g = {"tag": f"🎉{item}", "type": "selector", "outbounds": groups_item}
                auto_node.append(g["tag"])
            elif item == "VPS组":
                g = {"tag": "🚀VPS组", "type": "selector", "outbounds": groups_item}
                auto_node.append(g["tag"])
            elif item == "其它":
                g = {"tag": item, "type": "selector", "outbounds": groups_item}
            else:
                g = {"tag": item, "type": "urltest", "interval": "5m", "outbounds": groups_item}
                auto_node.append(item)
            if g.get("outbounds"):
                proxy_node.extend(g["outbounds"])
                proxyGroups.append(g)

        proxy_groups = []
        exclude = ("DIRECT", "REJECT")
        for group in self.config["proxy_groups"]:
            if not group.get("proxies") or group["name"] in exclude:
                continue
            group_type = "urltest" if group["type"] == "url-test" else "selector"
            rec = {"tag": group["name"], "type": group_type}
            if group_type == "urltest":
                rec["interval"] = "5m"
            if "interrupt_exist_connections" in group:
                rec["interrupt_exist_connections"] = group.get("interrupt_exist_connections")
            proxies = []
            for proxy in group["proxies"]:
                if proxy == "@全部节点":
                    proxies.extend(proxy_node)
                elif proxy == "@自动选择":
                    proxies.extend(auto_node)
                elif proxy == "@节点组":
                    proxies.extend(auto_node)
                    proxies.extend(fee_node)
                else:
                    proxies.append(proxy)
            if not proxies:
                proxies.extend(proxy_node)
            rec["outbounds"] = proxies
            proxy_groups.append(rec)

        proxy_groups.extend(proxyGroups)
        return proxy_groups

    def download_rule_file(self) -> dict:
        """
        获取规则配置文件
        """
        hosts = []
        if self.config.get("proxy_groups"):
            for x in self.config["proxy_groups"]:
                if x.get("hosts"):
                    hosts.extend(x["hosts"])
        if "other_rules" in self.config:
            for rules in self.config["other_rules"]:
                if rules.get("hosts"):
                    hosts.extend(rules["hosts"])
                if rules.get("rule_set"):
                    hosts.extend(rules["rule_set"])

        return utils.get_rule(hosts)

    def convert(self, params, nodes):
        """
        生成sing-box配置文件
        """
        sites = []
        if nodes:
            for node in nodes:
                sites.extend(node["content"])
                if node.get("headers"):
                    self.init_headers(node)

        socks5_port = params.get("socks5_port") or 7891
        fixed_node = params.get("fixed_node")
        config = self.config["singbox"]
        for inbound in config.get("inbounds", []):
            if inbound["type"] == "socks":
                inbound["listen_port"] = socks5_port

        servers = set()
        singbox_proxy = []
        for site in sites:
            pxy = site.to_singbox()
            if pxy:
                singbox_proxy.append(site)
                config["outbounds"].append(pxy)
                servers.add(site.address)

        proxy_group = self._proxy_groups(singbox_proxy)

        rule_files = self.download_rule_file()
        cfg_rules = []

        # 载入配置文件中的规则
        default_proxy_name = ""  # 默认项
        if self.config.get("proxy_groups"):
            for pxygrp in self.config["proxy_groups"]:
                if not default_proxy_name:
                    default_proxy_name = pxygrp["name"]
                if pxygrp.get("default"):
                    default_proxy_name = pxygrp["name"]

                # 从配置中获取规则
                add_rules = []
                if pxygrp.get("rule_set"):
                    cfg_rules.append({"rule_set": pxygrp["rule_set"], "outbound": pxygrp["name"]})
                else:
                    if pxygrp.get("hosts"):
                        for url in pxygrp["hosts"]:
                            filename = os.path.basename(url)
                            if filename in rule_files:
                                add_rules.extend(rule_files[filename])
                    if pxygrp.get("rules"):
                        add_rules.extend(pxygrp["rules"])

                rule_list = self.format_rule(add_rules)
                if rule_list:
                    rule_list["outbound"] = pxygrp["name"]
                    cfg_rules.append(rule_list)

        # 载入自定义规则
        if "other_rules" in self.config:
            for rules in self.config["other_rules"]:
                outbound = default_proxy_name if rules["path"] == "PROXY" else rules["path"]
                add_rules = []
                if "rule_set" in rules:
                    for url in rules.get("rule_set"):
                        filename = os.path.basename(url)
                        if filename in rule_files:
                            add_rules.extend(rule_files[filename])
                if "rules" in rules:
                    add_rules.extend(rules["rules"])
                rule_list = self.format_rule(add_rules)
                if rule_list:
                    rule_list["outbound"] = outbound
                    cfg_rules.append(rule_list)

        if fixed_node:
            default_proxy_name = "手动选择"
            config["outbounds"].extend(proxy_group[:2])
            newout = {"tag": "手动选择", "type": "selector", "outbounds": ["♻️ 自动选择", "🔰 节点选择"]}
            cfg_rules = [{"rule_set": ["proxy", "geosite-geolocation-!cn"], "outbound": default_proxy_name}]
            for outbound in config["outbounds"]:
                if outbound.get("tag") == fixed_node:
                    newout["outbounds"].insert(0, fixed_node)
                    break
            config["outbounds"].append(newout)
        else:
            config["outbounds"].extend(proxy_group)

        routes = config["route"]
        for rule in routes["rules"]:
            if isinstance(rule.get("outbound"), str):
                if rule["outbound"] == "proxy":
                    rule["outbound"] = default_proxy_name
            if isinstance(rule.get("outbound"), dict) and rule["outbound"].get("tag"):
                outbound = rule["outbound"]
                config["outbounds"].append(outbound)
                rule["outbound"] = rule["outbound"]["tag"]
        if routes.get("rule_set"):
            for x in routes["rule_set"]:
                if x.get("download_detour") == "proxy":
                    x["download_detour"] = default_proxy_name

        config["route"]["rules"].extend(cfg_rules)
        config["route"]["final"] = default_proxy_name
        # config["dns"]["servers"][0]["detour"] = default_proxy_name

        return {"headers": None, "body": config, "mimetype": "application/json"}


class Surge:
    def __init__(self) -> None:
        config_file = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "config.json")
        self.test_url = "http://www.gstatic.com/generate_204"
        self.test_interval = 43200
        self._headers = {}
        with open(config_file, "rt", encoding="utf-8") as f:
            self.config = json.load(f)
            self.countrys = {}
            for name, tags in self.config["countrys"].items():
                if isinstance(tags, str):
                    self.countrys[tags] = name
                if isinstance(tags, list):
                    for tag in tags:
                        self.countrys[tag] = name
            if self.config.get("proxy-test-url"):
                self.test_url = self.config["proxy-test-url"]
            if self.config.get("test-url"):
                self.test_url = self.config["test-url"]
            if self.config.get("test-interval"):
                self.test_interval = self.config["test-interval"]

    def init_headers(self, subscribe):
        if self._headers:
            return

        self._headers = subscribe["headers"]

    def format_rule(self, lines: list, sort=True):
        """
        对rule数据进行拼装
        """
        rules = []
        ip_rules = []
        new_lines = []
        if sort:
            new_lines = sorted(list(set(lines)))
        else:
            unique_check = set()
            for line in lines:
                if line in unique_check:
                    continue
                unique_check.add(line)
                new_lines.append(line)
        for line in new_lines:
            if not line:
                continue
            s = line.strip()
            if (
                s.startswith("DOMAIN")
                or s.startswith("ASN")
                or s.startswith("SRC-IP")
                or s.startswith("GEOIP")
                or s.startswith("USER-AGENT")
                or s.startswith("URL-REGEX")
                or s.startswith("RULE-SET")
                or s.startswith("PROCESS-NAME")
            ):
                rules.append(f"{s},%s")
            elif s.startswith("IP-CIDR") or s.startswith("IP-CIDR6"):
                rule = list(map(str.strip, s.split(",")))
                if rule[-1] == "no-resolve":
                    ip_rules.append("{},%s,{}".format(",".join(rule[:-1]), rule[-1]))
                else:
                    ip_rules.append(f"{s},%s")
        return rules, ip_rules

    def _proxy_groups(self, proxies):
        """
        代理组
        """
        groups = collections.defaultdict(list)
        nodeNames = [x.name for x in proxies]

        addNodes = set()
        for p in nodeNames:
            upp = p.upper()
            if upp.find("TEST") >= 0 or p.find("测试") >= 0:
                addNodes.add(p)
                groups["测试线路"].append(p)
            elif upp.find("VIP") >= 0:
                addNodes.add(p)
                groups["VIP专线"].append(p)
            elif upp.find("IPLC") >= 0:
                addNodes.add(p)
                groups["IPLC专线"].append(p)
            elif upp.find("IEPL") >= 0:
                addNodes.add(p)
                groups["IPLC专线"].append(p)
            elif upp.find("VPS") >= 0:
                addNodes.add(p)
                groups["VPS组"].append(p)
        n = set(nodeNames) - addNodes
        nodeNames = [x for x in nodeNames if x in n]

        # 收集各国专线
        youhui_pattern = re.compile(r"0\.\d+?")
        duobei_pattern = re.compile(r"[x][2-9]|[x][1-9]\d+?|[2-9][xX]|[1-9]\d+?[xX]")
        for name, flag in self.countrys.items():
            addNodes = set()
            for p in nodeNames:
                if p.find(name) >= 0:
                    addNodes.add(p)
                    if youhui_pattern.search(p):
                        groups["优惠线路"].append(p)
                    elif duobei_pattern.search(p):
                        groups["多倍扣费"].append(p)
                    elif p.find("倍") >= 0:
                        groups["多倍扣费"].append(p)
                    else:
                        groups[flag].append(p)
            n = set(nodeNames) - addNodes
            nodeNames = [x for x in nodeNames if x in n]

        # 剩余解析不了的，全部归入其它
        groups["其它"] = list(nodeNames)

        proxy_node = []  # 所有代理节点
        auto_node = []  # 汇入自动选择的节点
        fee_node = []  # 多倍付费节点
        proxyGroups = []

        for item in groups.keys():
            g = {}
            groups_item = sorted(groups[item])
            if item == "多倍扣费":
                g = {"name": f"💵{item}", "type": "select", "proxies": groups_item}
                fee_node.append(g["name"])
            elif item == "优惠线路":
                g = {"name": f"🎠{item}", "type": "select", "proxies": groups_item}
                auto_node.append(g["name"])
            elif item == "测试线路":
                g = {"name": "🪲测试组", "type": "select", "proxies": groups_item}
                auto_node.append(g["name"])
            elif item == "VIP专线":
                g = {"name": f"👑{item}", "type": "select", "proxies": groups_item}
                auto_node.append(g["name"])
            elif item == "IPLC专线":
                g = {"name": f"🎉{item}", "type": "select", "proxies": groups_item}
                auto_node.append(g["name"])
            elif item == "IEPL线路":
                g = {"name": f"🎉{item}", "type": "select", "proxies": groups_item}
                auto_node.append(g["name"])
            elif item == "VPS组":
                g = {"name": "🚀VPS组", "type": "select", "proxies": groups_item}
                auto_node.append(g["name"])
            elif item == "其它":
                g = {"name": item, "type": "select", "proxies": groups_item}
            else:
                g = {"name": item, "type": "url-test", "proxies": groups_item}
                auto_node.append(item)
            if g.get("proxies"):
                proxy_node.extend(g["proxies"])
                proxyGroups.append(g)

        proxy_groups = {}
        exclude = ("DIRECT", "REJECT")
        for group in self.config["proxy_groups"]:
            if not group.get("proxies") or group["name"] in exclude:
                continue
            proxies = [group["type"]]
            for proxy in group["proxies"]:
                if proxy == "@全部节点":
                    proxies.extend(proxy_node)
                elif proxy == "@自动选择":
                    proxies.extend(auto_node)
                elif proxy == "@节点组":
                    proxies.extend(auto_node)
                    proxies.extend(fee_node)
                else:
                    proxies.append(proxy)
            if not proxies:
                proxies.extend(proxy_node)
            if group["type"] == "url-test":
                proxies.append(f"url={self.test_url}")
                proxies.append(f"interval={self.test_interval}")
            proxy_groups[group["name"]] = ", ".join(proxies)

        for group in proxyGroups:
            proxies = [group["type"]]
            proxies.extend(group["proxies"])
            if group["type"] == "url-test":
                proxies.append(f"url={self.test_url}")
                proxies.append(f"interval={self.test_interval}")
            proxy_groups[group["name"]] = ", ".join(proxies)
        return proxy_groups

    def download_rule_file(self) -> dict:
        """
        获取规则配置文件
        """
        hosts = []
        if self.config.get("proxy_groups"):
            for x in self.config["proxy_groups"]:
                if x.get("hosts"):
                    hosts.extend(x["hosts"])
        if "other_rules" in self.config:
            for rules in self.config["other_rules"]:
                if rules.get("hosts"):
                    hosts.extend(rules["hosts"])
        if self.config.get("surge", {}).get("ads_rule"):
            ads_rule = self.config["surge"]["ads_rule"]
            if ads_rule.get("hosts"):
                hosts.extend(ads_rule["hosts"])
        return utils.get_rule(hosts)

    def convert(self, params, nodes):
        """
        生成surge配置文件
        """
        sites = []
        if nodes:
            for node in nodes:
                sites.extend(node["content"])
                if node.get("headers"):
                    self.init_headers(node)

        template_file = os.path.join(os.getcwd(), "surge.tmpl")
        config = configparser.RawConfigParser(allow_no_value=True)
        config.optionxform = str
        config.read(template_file, encoding="utf-8")

        if self.config.get("surge", {}).get("General"):
            for k, v in self.config["surge"]["General"].items():
                config["General"][k] = v
        if not config["General"].get("dns_server"):
            config["General"]["dns_server"] = params.get("dns_server") or "system"

        config_proxy = []
        config_proxy_group = []
        config_rule = []

        servers = set()
        surge_proxy = []
        for site in sites:
            pxy = site.to_surge()
            if pxy:
                surge_proxy.append(site)
                config_proxy.append(pxy)
                servers.add(site.address)

        proxy_group = self._proxy_groups(surge_proxy)
        for k, v in proxy_group.items():
            config_proxy_group.append(f"{k}={v}")

        rule_files = self.download_rule_file()
        cfg_rules = ["RULE-SET,LAN,DIRECT"]

        # 载入广告规则
        if self.config.get("surge", {}).get("ads_rule"):
            ads_rule = self.config["surge"]["ads_rule"]
            rules = []
            if ads_rule.get("hosts"):
                for url in ads_rule["hosts"]:
                    filename = os.path.basename(url)
                    if filename in rule_files:
                        rules.extend(rule_files[filename])
            if ads_rule.get("rules"):
                rules.extend(ads_rule["rules"])
            rule_list, ip_rule_list = self.format_rule(rules)
            for rule in rule_list:
                cfg_rules.append(rule % "REJECT-TINYGIF")
            for rule in ip_rule_list:
                cfg_rules.append(rule % "REJECT-TINYGIF")

            if "rule_set" in ads_rule:
                for x in ads_rule.get("rule_set"):
                    cfg_rules.append(f"RULE-SET,{x},REJECT-TINYGIF,update-interval=43200")
            if "domain_set" in ads_rule:
                for x in ads_rule.get("domain_set"):
                    cfg_rules.append(f"DOMAIN-SET,{x},REJECT-TINYGIF,update-interval=43200")

        # 载入提供服务的站点直连规则
        """ svrips = {x for x in servers if utils.check_ip(x)}
        domains = {".".join(x.split(".")[1:]) for x in servers - svrips if x and x.find(".") > 0}
        for x in domains:
            cfg_rules.append(f"DOMAIN-SUFFIX,{x},DIRECT")
        for x in svrips:
            cfg_rules.append(f"IP-CIDR,{x}/32,DIRECT,no-resolve") """

        # 载入配置文件中的规则
        default_proxy_name = ""  # 默认项
        if self.config.get("proxy_groups"):
            for pxygrp in self.config["proxy_groups"]:
                if not default_proxy_name:
                    default_proxy_name = pxygrp["name"]
                if pxygrp.get("default"):
                    default_proxy_name = pxygrp["name"]

                # 从配置中获取规则
                rules = []
                if pxygrp.get("hosts"):
                    for url in pxygrp["hosts"]:
                        filename = os.path.basename(url)
                        if filename in rule_files:
                            rules.extend(rule_files[filename])
                if pxygrp.get("rules"):
                    rules.extend(pxygrp["rules"])

                rule_list, ip_rule_list = self.format_rule(rules)
                for rule in rule_list:
                    cfg_rules.append(rule % pxygrp["name"])
                for rule in ip_rule_list:
                    cfg_rules.append(rule % pxygrp["name"])
                if pxygrp.get("fixed_rules"):
                    cfg_rules.extend(pxygrp["fixed_rules"])

                if "rule_set" in pxygrp:
                    for x in pxygrp.get("rule_set"):
                        cfg_rules.append("RULE-SET,{},{},update-interval=43200".format(x, pxygrp["name"]))
                if "domain_set" in pxygrp:
                    for x in pxygrp.get("domain_set"):
                        cfg_rules.append("DOMAIN-SET,{},{},update-interval=43200".format(x, pxygrp["name"]))

        # 载入内网直连规则
        if "other_rules" in self.config:
            for rules in self.config["other_rules"]:
                outbound = default_proxy_name if rules["path"] == "PROXY" else rules["path"]
                add_rules = []
                if "hosts" in rules:
                    for url in rules["hosts"]:
                        filename = os.path.basename(url)
                        if filename in rule_files:
                            add_rules.extend(rule_files[filename])
                if "rules" in rules:
                    add_rules.extend(rules["rules"])
                rule_list, ip_rule_list = self.format_rule(add_rules)
                for rule in rule_list:
                    cfg_rules.append(rule % outbound)
                for rule in ip_rule_list:
                    cfg_rules.append(rule % outbound)

                if "rule_set" in rules:
                    for x in rules.get("rule_set"):
                        cfg_rules.append("RULE-SET,{},{},update-interval=3600".format(x, outbound))
                if "domain_set" in rules:
                    for x in rules.get("domain_set"):
                        cfg_rules.append("DOMAIN-SET,{},{},update-interval=3600".format(x, outbound))

        config_rule = [rule for rule in cfg_rules]
        config_rule.append("GEOIP,CN,DIRECT")
        config_rule.append(f"FINAL,{default_proxy_name},dns-failed")

        # 返回配置文本
        content = []
        for section in config.sections():
            content.append("")
            content.append(f"[{section}]")
            for key, value in config[section].items():
                if value is None:
                    content.append(key)
                elif isinstance(value, bool) or value in ("True", "False"):
                    content.append("{} = {}".format(key, "true" if value is True or value == "True" else "false"))
                else:
                    content.append(f"{key} = {value}")

        if config_proxy:
            content.append("\n[Proxy]")
            content.extend(config_proxy)
        if config_proxy_group:
            content.append("\n[Proxy Group]")
            content.extend(config_proxy_group)
        if config_rule:
            content.append("\n[Rule]\n# 自定义规则\n# 您可以在此处插入自定义规则")
            content.extend(config_rule)
        # 配置重定向
        if self.config.get("surge", {}).get("url_rewrite"):
            content.append("\n[URL Rewrite]")
            content.extend(self.config["surge"]["url_rewrite"])
        # MITM
        if self.config.get("MITM"):
            content.append("\n[MITM]")
            content.extend(self.config["MITM"])

        if self._headers.get("filename"):
            title = self._headers["filename"]
        if "userinfo" in self._headers:
            userinfo = self._headers["userinfo"]
            userinfo["title"] = title
            panel_content = "SubscribeInfo = title={title}, content=上传流量：{upload}GB\\n下载流量：{download}GB\\n剩余流量：{balance}GB\\n套餐流量：{total}GB\\n到期时间：{expire}, style=info"
            panel_content = panel_content.format(**userinfo)
            content = "[Panel]\n{}\n\n{}".format(panel_content, "\n".join(content))

        url = params["url"]
        url = "https{}".format(url[4:]) if url.startswith("http:") else url
        sub_body = f"#!MANAGED-CONFIG {url} interval=43200 strict=true\n\n\n{content}"

        return {"headers": None, "body": sub_body, "mimetype": "text/plain"}


class Mihomo:
    def __init__(self, fileName=None) -> None:
        self._headers = {}
        self.test_interval = 14400
        config_file = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "config.json")
        with open(config_file, "rt", encoding="utf-8") as f:
            self.config = json.load(f)
            self.countrys = {}
            for name, tags in self.config["countrys"].items():
                if isinstance(tags, str):
                    self.countrys[tags] = name
                if isinstance(tags, list):
                    for tag in tags:
                        self.countrys[tag] = name
            if self.config.get("test-interval"):
                self.test_interval = self.config["test-interval"]
        if fileName and os.path.exists(fileName):
            f = open(fileName, "r", encoding="utf-8")
            self._stream = f.read()
            f.close()

    def _yaml_load(self):
        return ordered_yaml_load(self._stream)

    def _yaml_dump(self, data):
        return ordered_yaml_dump(data, allow_unicode=True, default_flow_style=False)

    def _parse_ss(self, url):
        node = dict()
        node["name"] = unquote(url.fragment)
        node["server"] = url.hostname
        node["port"] = url.port
        node["type"] = url.scheme
        userpass = utils.b64decode(url.username).split(":")
        node["cipher"] = userpass[0]
        node["password"] = userpass[1]
        return node

    def _parse_trojan(self, url):
        node = dict()
        query = dict(parse_qsl(url.query))
        node["name"] = unquote(url.fragment)
        node["server"] = url.hostname
        node["port"] = url.port
        node["type"] = "trojan"
        node["password"] = url.username
        node["udp"] = True
        if query.get("sni"):
            node["sni"] = query["sni"]
        node["skip-cert-verify"] = False
        if query.get("allowInsecure"):
            node["skip-cert-verify"] = True
        return node

    def _parse_vmess(self, url):
        node = dict()
        info = json.loads(utils.b64decode(url[8:]))
        node["name"] = info["ps"]
        node["server"] = info["add"]
        node["port"] = info["port"] or "443"
        node["type"] = "vmess"
        node["uuid"] = info["id"]
        node["alterId"] = info.get("aid") or "0"
        node["cipher"] = info.get("scy") or "auto"
        node["udp"] = True
        node["network"] = info["net"]
        path = info.get("path") or "/"
        if info.get("tls"):
            node["tls"] = True
        if node["network"] == "ws":
            opts = dict()
            opts["path"] = path
            if info.get("host"):
                opts["headers"] = {"Host": info["host"]}
            node["ws-opts"] = opts
        if node["network"] == "h2":
            opts = dict()
            opts["path"] = path
            if info.get("host"):
                opts["host"] = list(map(str.strip, info["host"].split(",")))
            node["h2-opts"] = opts
        node["port"] = int(node["port"])
        node["alterId"] = int(node["alterId"])
        return node

    def _parse_vless(self, url):
        node = dict()
        query = dict(parse_qsl(url.query))
        path = query.get("path") or "%2F"
        path = unquote(path)
        network = query.get("type") or "http"
        node["name"] = unquote(url.fragment)
        node["server"] = url.hostname
        node["port"] = url.port
        node["type"] = url.scheme
        node["uuid"] = url.username
        if query.get("sni"):
            node["servername"] = query["sni"]
        security = query.get("security")
        if security == "xtls":
            node["flow"] = query.get("flow") or "xtls-rprx-direct"
        elif security == "tls":
            node["tls"] = True
            node["udp"] = True
            node["network"] = network
            if network == "ws":
                opts = dict()
                opts["path"] = path
                if query.get("host"):
                    opts["headers"] = {"Host": unquote(query["host"])}
                node["ws-opts"] = opts
            elif network == "http":
                opts = dict()
                opts["path"] = path
                if query.get("host"):
                    opts["headers"] = {"Host": unquote(query["host"])}
                node["h2-opts"] = opts
            elif network == "grpc":
                opts = dict()
                opts["grpc-service-name"] = unquote(query["host"])
                node["grpc-opts"] = opts
        return node

    def _parse_hysteria2(self, url):
        # hysteria2://bc8bf32e-ce01-4345-8e06-8d8cb03634e7@163.123.192.149:443/?insecure=1&sni=apps.apple.com#%E5%89%A9%E4%BD%99%E6%B5%81%E9%87%8F%EF%BC%9A999.83%20GB
        query = dict(parse_qsl(url.query))
        path = query.get("path") or "%2F"
        path = unquote(path)
        node = {
            "name": unquote(url.fragment),
            "server": url.hostname,
            "port": url.port,
            "type": url.type,
            "password": url.username,
        }
        if query.get("sni"):
            node["sni"] = query["sni"]
        if query.get("insecure"):
            node["skip-cert-verify"] = query["sni"] in ["1", 1, "true"]
        return node

    def _clash_decode(self, s):
        if not s:
            return None
        o = urlsplit(s)
        t = o.scheme
        try:
            if t == "ss":
                return self._parse_ss(o)
            elif t == "trojan" or t == "trojan-go":
                return self._parse_trojan(o)
            elif t == "vmess":
                return self._parse_vmess(s)
            elif t == "vless":
                return self._parse_vless(o)
        except Exception as e:
            logger.error(e)
        return None

    def format_rule(self, lines: list):
        """
        对rule数据进行拼装
        """
        rules = []
        ip_rules = []
        for line in lines:
            if not line:
                continue
            s = line.strip()
            if s.startswith("DOMAIN") or s.startswith("SOURCE") or s.startswith("GEOIP"):
                rules.append(f"{s},%s")
            elif s.startswith("IP-CIDR"):
                rule = list(map(str.strip, s.split(",")))
                if rule[-1] == "no-resolve":
                    ip_rules.append("{},%s,{}".format(",".join(rule[:-1]), rule[-1]))
                else:
                    ip_rules.append(f"{s},%s")
        return rules, ip_rules

    def get_rule(self, files=[], rules=[]):
        all_rules = []
        if rules:
            all_rules.extend(rules)
        if files:
            for filepath in files:
                if not os.path.exists(filepath):
                    continue
                # 从下载的文件中读取配置项
                with open(filepath, "rt", encoding="utf-8") as f:
                    lines = f.readlines()
                    if lines:
                        all_rules.extend(lines)

        rule_list, ip_rule_list = self.format_rule(all_rules)
        rule_list = sorted(list(set(rule_list)))
        if ip_rule_list:
            rule_list.extend(sorted(list(set(ip_rule_list))))
        return rule_list

    def _clash_proxies(self, nodes):
        """
        解析clash格式节点数据
        """
        proxies = []
        for node in nodes:
            proxy = self._clash_decode(node)
            if proxy:
                proxies.append(proxy)
        return proxies

    def _clash_proxy_groups(self, proxies, cfg_groups):
        """
        clash 代理组
        """
        test_params = {"url": "http://www.gstatic.com/generate_204", "interval": 3600}

        groups = collections.defaultdict(list)
        nodeNames = [x["name"] for x in proxies if x.get("name")]

        addNodes = set()
        for p in nodeNames:
            upp = p.upper()
            if upp.find("TEST") >= 0 or p.find("测试") >= 0:
                addNodes.add(p)
                groups["测试线路"].append(p)
            elif upp.find("VIP") >= 0:
                addNodes.add(p)
                groups["VIP专线"].append(p)
            elif upp.find("IPLC") >= 0:
                addNodes.add(p)
                groups["IPLC专线"].append(p)
            elif upp.find("IEPL") >= 0:
                addNodes.add(p)
                groups["IPLC专线"].append(p)
            elif upp.find("VPS") >= 0:
                addNodes.add(p)
                groups["VPS组"].append(p)
        n = set(nodeNames) - addNodes
        nodeNames = [x for x in nodeNames if x in n]

        # 收集各国专线
        youhui_pattern = re.compile(r"0\.\d+?")
        duobei_pattern = re.compile(r"[x][2-9]|[x][1-9]\d+?|[2-9][xX]|[1-9]\d+?[xX]")
        for name, flag in self.countrys.items():
            addNodes = set()
            for p in nodeNames:
                if p.find(name) >= 0:
                    addNodes.add(p)
                    if youhui_pattern.search(p):
                        # groups[f"{flag}优惠"].append(p)
                        groups["优惠线路"].append(p)
                    elif duobei_pattern.search(p):
                        groups["多倍扣费"].append(p)
                    elif p.find("倍") >= 0:
                        groups["多倍扣费"].append(p)
                    # elif p.find("专线") >= 0:
                    #     groups[f"{flag}专线"].append(p)
                    else:
                        groups[flag].append(p)
            n = set(nodeNames) - addNodes
            nodeNames = [x for x in nodeNames if x in n]

        # 剩余解析不了的，全部归入其它
        groups["其它"] = list(nodeNames)

        allNodes = []
        autoNodes = []
        multiNodes = []
        proxyGroups = []
        for item in groups.keys():
            g = {}
            if item == "多倍扣费":
                g = {"name": f"💵{item}", "type": "select", "proxies": sorted(groups[item])}
                multiNodes.append(g["name"])
            elif item == "优惠线路":
                g = {"name": f"🎠{item}", "type": "select", "proxies": sorted(groups[item])}
                autoNodes.append(g["name"])
            elif item == "测试线路":
                g = {"name": "🪲测试组", "type": "select", "proxies": sorted(groups[item])}
                autoNodes.append(g["name"])
            elif item == "VIP专线":
                g = {"name": f"👑{item}", "type": "select", "proxies": sorted(groups[item])}
                autoNodes.append(g["name"])
            elif item == "IPLC专线":
                g = {"name": f"🎉{item}", "type": "select", "proxies": sorted(groups[item])}
                autoNodes.append(g["name"])
            elif item == "IEPL线路":
                g = {"name": f"🎉{item}", "type": "select", "proxies": sorted(groups[item])}
                autoNodes.append(g["name"])
            elif item == "VPS组":
                g = {"name": "🚀VPS组", "type": "select", "proxies": sorted(groups[item])}
                autoNodes.append(g["name"])
            elif item == "其它":
                g = {"name": item, "type": "select", "proxies": sorted(groups[item])}
            else:
                g = {"name": item, "type": "url-test", "proxies": sorted(groups[item]), **test_params}
                autoNodes.append(item)
            if g.get("proxies"):
                allNodes.extend(g["proxies"])
                proxyGroups.append(g)

        result = []
        exclude = ("DIRECT", "REJECT")
        for group in cfg_groups:
            if not group.get("proxies") or group["name"] in exclude:
                continue
            rec = group.copy()
            if rec.get("hosts"):
                rec.pop("hosts")
            if rec.get("rules"):
                rec.pop("rules")
            proxies = []
            for proxy in rec["proxies"]:
                if proxy == "@全部节点":
                    proxies.extend(allNodes)
                elif proxy == "@自动选择":
                    proxies.extend(autoNodes)
                elif proxy == "@节点组":
                    proxies.extend(autoNodes)
                    proxies.extend(multiNodes)
                else:
                    proxies.append(proxy)
            if not proxies:
                proxies.extend(allNodes)
            rec["proxies"] = proxies
            if rec["type"] == "url-test":
                rec.update(test_params)
            result.append(rec)
        result.extend(proxyGroups)
        return result

    def rules_local_netware(self):
        rules = "DOMAIN-SUFFIX,ip6-localhost,DIRECT DOMAIN-SUFFIX,ip6-loopback,DIRECT DOMAIN-SUFFIX,lan,DIRECT DOMAIN-SUFFIX,local,DIRECT DOMAIN-SUFFIX,localhost,DIRECT DOMAIN,instant.arubanetworks.com,DIRECT DOMAIN,setmeup.arubanetworks.com,DIRECT DOMAIN,router.asus.com,DIRECT DOMAIN-SUFFIX,hiwifi.com,DIRECT DOMAIN-SUFFIX,leike.cc,DIRECT DOMAIN-SUFFIX,miwifi.com,DIRECT DOMAIN-SUFFIX,my.router,DIRECT DOMAIN-SUFFIX,p.to,DIRECT DOMAIN-SUFFIX,peiluyou.com,DIRECT DOMAIN-SUFFIX,phicomm.me,DIRECT DOMAIN-SUFFIX,router.ctc,DIRECT DOMAIN-SUFFIX,routerlogin.com,DIRECT DOMAIN-SUFFIX,tendawifi.com,DIRECT DOMAIN-SUFFIX,zte.home,DIRECT DOMAIN-SUFFIX,tplogin.cn,DIRECT"
        return rules.split()

    def rules_suffix(self, proxyName):
        """
        后续添加的规则
        """
        return [
            "DOMAIN-KEYWORD,aria2,DIRECT",
            "DOMAIN-KEYWORD,xunlei,DIRECT",
            "DOMAIN-KEYWORD,yunpan,DIRECT",
            "DOMAIN-KEYWORD,Thunder,DIRECT",
            "DOMAIN-KEYWORD,XLLiveUD,DIRECT",
            "GEOIP,CN,DIRECT",
            f"MATCH,{proxyName}",
        ]

    def rule_config(self):
        """
        解析配置文件
        """
        cfg = self.config
        if cfg.get("proxy_groups"):
            hosts = []
            for x in cfg["proxy_groups"]:
                if x.get("hosts"):
                    hosts.extend(x["hosts"])
            utils.get_rule(hosts)
        return cfg

    def cleanNullNode(self, node):
        """
        清除字典中的空值
        """
        if not isinstance(node, dict):
            return node
        result = node.copy()
        for k in list(result.keys()):
            if isinstance(result[k], dict):
                result[k] = self.cleanNullNode(result[k])
            if not result[k]:
                result.pop(k)
        return result

    def download_rule_file(self) -> dict:
        """
        获取规则配置文件
        """
        hosts = []
        if self.config.get("proxy_groups"):
            for x in self.config["proxy_groups"]:
                if x.get("hosts"):
                    hosts.extend(x["hosts"])
        if "other_rules" in self.config:
            for rules in self.config["other_rules"]:
                if rules.get("hosts"):
                    hosts.extend(rules["hosts"])
                if rules.get("rule_set"):
                    hosts.extend(rules["rule_set"])

        return utils.get_rule(hosts)

    def init_headers(self, subinfo):
        """
        从源订阅网站获取订阅详情
        """
        if self._headers:
            return

        urlinfo = subinfo["urlinfo"]
        query = dict(parse_qsl(urlinfo.query))
        if not urlinfo.path == "/api/v1/client/subscribe":
            return

        query["flag"] = "clash"
        n = list(urlinfo[:])
        n[3] = "&".join([f"{k}={v}" for k, v in query.items()])
        new_url = urlunsplit(n)
        try:
            response = utils.get(new_url)
            headers = response["headers"]

            if "content-disposition" in headers:
                contentDisposition = headers["content-disposition"]
                filename = re.findall("filename\\u002A=[a-zA-z]+-[8]''(.+)", contentDisposition)
                if filename:
                    headers["filename"] = unquote(filename[0])

                    content_disposition_filename = filename[0]
                    if content_disposition_filename != headers["filename"]:
                        self._headers["content-disposition"] = (
                            f"attachment; filename*=utf-8''{content_disposition_filename}"
                        )
                    else:
                        self._headers["content-disposition"] = 'attachment; filename="{}"'.format(headers["filename"])

            if "subscription-userinfo" in headers:
                subscriptionUserinfo = headers["subscription-userinfo"]
                self._headers["subscription-userinfo"] = subscriptionUserinfo

            # 如果响应头中存在profile-update-interval字段，则配置文件自动更新间隔设置为对应的值，以小时为单位
            self._headers["profile-update-interval"] = headers.get("profile-update-interval") or 24

            # 如果响应头中存在profile-web-page-url字段，则在右键点击 profile 菜单中会显示Open web page选项，允许用户跳转到对应的门户首页
            self._headers["profile-web-page-url"] = headers.get("profile-web-page-url") or new_url
            try:
                self._headers["profile-web-page-url"].encode("latin-1")
            except Exception:
                self._headers["profile-web-page-url"] = quote(self._headers["profile-web-page-url"])

        except Exception:
            pass

    def convert(self, params, nodes):
        sites = []
        for node in nodes:
            if node:
                sites.extend(node["content"])
                self.init_headers(node)

        socks5_port = params.get("socks5_port") or 7890
        content = {
            "mixed-port": socks5_port,
            "allow-lan": True,
            "mode": "rule",
            "log-level": "info",
            "external-controller": "0.0.0.0:9090",
            "dns": {},
            "proxies": [],
        }
        for site in sites:
            if params.get("no_rprx") and site._scheme == "vless" and site.flow == "xtls-rprx-vision":
                continue
            proxie = site.to_mihomo()
            if proxie:
                content["proxies"].append(proxie)
        servers = {x["server"] for x in content["proxies"] if x.get("server")}
        svrips = {x for x in servers if utils.check_ip(x)}
        domains = {".".join(x.split(".")[-2:]) for x in servers - svrips if x}

        # 根据配置文件调整
        default_proxy = ""
        cfg_groups = []
        cfg_providers = {}
        cfg_rules = [
            "IP-CIDR,198.18.0.1/16,REJECT,no-resolve",
            "GEOIP,private,DIRECT,no-resolve",
        ]
        rule_files = self.download_rule_file()
        for x in domains:
            cfg_rules.append(f"DOMAIN-SUFFIX,{x},DIRECT")
        for x in svrips:
            cfg_rules.append(f"IP-CIDR,{x}/32,DIRECT,no-resolve")
        cfg_rules.extend(self.rules_local_netware())
        cfg = self.rule_config()
        if cfg.get("ws-opts"):
            # 如果存在免流配置，就更新vmess 80端口且ws协议的免流参数
            for p in content["proxies"]:
                if p.get("ws-opts") and p["type"] == "vmess" and p["port"] == 80 and p.get("network") == "ws":
                    p["ws-opts"].update(cfg["ws-opts"])
                    p["ws-opts"] = self.cleanNullNode(p["ws-opts"])
            # result["proxies"] = json.loads(json.dumps(result["proxies"]))
        if cfg.get("proxy_groups"):
            cfg_groups = cfg["proxy_groups"]
            for x in cfg_groups:
                if not default_proxy:
                    default_proxy = x["name"]
                if x.get("default"):
                    default_proxy = x["name"]

                # 从文件或配置中获取规则
                files = []
                if x.get("hosts"):
                    pages = utils.get_rule(x["hosts"])
                    files = [page for page in pages if page]
                group_rules = x["rules"] if x.get("rules") else []
                rules = self.get_rule(files=files, rules=group_rules)
                if rules:
                    for r in rules:
                        cfg_rules.append(r % x["name"])
        # 载入自定义规则
        if "other_rules" in cfg:
            for rules in cfg["other_rules"]:
                outbound = default_proxy if rules["path"] == "PROXY" else rules["path"]
                add_rules = []
                if "rule_set" in rules:
                    for url in rules.get("rule_set"):
                        filename = os.path.basename(url)
                        if filename in rule_files:
                            add_rules.extend(rule_files[filename])
                if "rules" in rules:
                    add_rules.extend(rules["rules"])
                rule_list, ip_rule_list = self.format_rule(add_rules)
                for rule in rule_list:
                    cfg_rules.append(rule % outbound)
                for rule in ip_rule_list:
                    cfg_rules.append(rule % outbound)
        if cfg.get("mihomo", {}).get("rule-providers"):
            for k, v in cfg["mihomo"]["rule-providers"].items():
                provider = v
                provider.setdefault("interval", 3600)
                proxy = "DIRECT"
                if provider.get("proxy"):
                    proxy = provider.pop("proxy")
                if proxy.lower() == "proxy":
                    proxy = default_proxy
                cfg_rules.append("RULE-SET,{},{}".format(k, proxy))
                cfg_providers[k] = provider
        if cfg.get("mihomo", {}).get("dns"):
            content["dns"] = cfg["mihomo"]["dns"]
        else:
            content.pop("dns")

        content["proxy-groups"] = self._clash_proxy_groups(content["proxies"], cfg_groups)

        # 唯一检查
        unique_check = set()
        unique_rules = []
        for rule in cfg_rules:
            if rule in unique_check:
                continue
            unique_check.add(rule)
            unique_rules.append(rule)

        if cfg_providers:
            content["rule-providers"] = cfg_providers
        content["rules"] = unique_rules
        content["rules"].extend(self.rules_suffix(default_proxy))

        return {"headers": self._headers, "body": content, "mimetype": "application/yaml"}


class Clash:
    def __init__(self, fileName=None) -> None:
        self._platform = "undefine"
        self._headers = {}
        self.test_interval = 14400
        config_file = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "config.json")
        with open(config_file, "rt", encoding="utf-8") as f:
            self.config = json.load(f)
            self.countrys = {}
            for name, tags in self.config["countrys"].items():
                if isinstance(tags, str):
                    self.countrys[tags] = name
                if isinstance(tags, list):
                    for tag in tags:
                        self.countrys[tag] = name
            if self.config.get("test-interval"):
                self.test_interval = self.config["test-interval"]
        if fileName and os.path.exists(fileName):
            f = open(fileName, "r", encoding="utf-8")
            self._stream = f.read()
            f.close()

    @property
    def platform(self):
        return self._platform

    @platform.setter
    def platform(self, platform):
        self._platform = platform

    def _yaml_load(self):
        return ordered_yaml_load(self._stream)

    def _yaml_dump(self, data):
        return ordered_yaml_dump(data, allow_unicode=True, default_flow_style=False)

    def _parse_ss(self, url):
        node = dict()
        node["name"] = unquote(url.fragment)
        node["server"] = url.hostname
        node["port"] = url.port
        node["type"] = url.scheme
        userpass = utils.b64decode(url.username).split(":")
        node["cipher"] = userpass[0]
        node["password"] = userpass[1]
        return node

    def _parse_trojan(self, url):
        node = dict()
        query = dict(parse_qsl(url.query))
        node["name"] = unquote(url.fragment)
        node["server"] = url.hostname
        node["port"] = url.port
        node["type"] = "trojan"
        node["password"] = url.username
        node["udp"] = True
        if query.get("sni"):
            node["sni"] = query["sni"]
        node["skip-cert-verify"] = False
        if query.get("allowInsecure"):
            node["skip-cert-verify"] = True
        return node

    def _parse_vmess(self, url):
        node = dict()
        info = json.loads(utils.b64decode(url[8:]))
        node["name"] = info["ps"]
        node["server"] = info["add"]
        node["port"] = info["port"] or "443"
        node["type"] = "vmess"
        node["uuid"] = info["id"]
        node["alterId"] = info.get("aid") or "0"
        node["cipher"] = info.get("scy") or "auto"
        node["udp"] = True
        node["network"] = info["net"]
        path = info.get("path") or "/"
        if info.get("tls"):
            node["tls"] = True
        # else:
        #     node["skip-cert-verify"] = True
        if node["network"] == "ws":
            opts = dict()
            opts["path"] = path
            # opts["max-early-data"] = 2048
            # opts["early-data-header-name"] = "Sec-WebSocket-Protocol"
            if info.get("host"):
                # if self.platform not in ("linux", "macos"):
                opts["headers"] = {"Host": info["host"]}
            node["ws-opts"] = opts
            # node["ws-path"] = path
            # if info.get("host"):
            #     node["ws-headers"] = {"Host": info["host"]}
        if node["network"] == "h2":
            opts = dict()
            opts["path"] = path
            if info.get("host"):
                opts["host"] = list(map(str.strip, info["host"].split(",")))
            node["h2-opts"] = opts
        node["port"] = int(node["port"])
        node["alterId"] = int(node["alterId"])
        return node

    def _parse_vless(self, url):
        node = dict()
        query = dict(parse_qsl(url.query))
        path = query.get("path") or "%2F"
        path = unquote(path)
        network = query.get("type") or "http"
        # { udp: true, sni: 13-251-128-188.nhost.00cdn.com, : true }
        node["name"] = unquote(url.fragment)
        node["server"] = url.hostname
        node["port"] = url.port
        node["type"] = url.scheme
        node["uuid"] = url.username
        if query.get("sni"):
            node["servername"] = query["sni"]
        security = query.get("security")
        if security == "xtls":
            node["flow"] = query.get("flow") or "xtls-rprx-direct"
        elif security == "tls":
            node["tls"] = True
            node["udp"] = True
            node["network"] = network
            if network == "ws":
                opts = dict()
                opts["path"] = path
                if query.get("host"):
                    opts["headers"] = {"Host": unquote(query["host"])}
                node["ws-opts"] = opts
            elif network == "http":
                opts = dict()
                opts["path"] = path
                if query.get("host"):
                    opts["headers"] = {"Host": unquote(query["host"])}
                node["h2-opts"] = opts
            elif network == "grpc":
                opts = dict()
                opts["grpc-service-name"] = unquote(query["host"])
                node["grpc-opts"] = opts

        return node

    def _clash_decode(self, s):
        if not s:
            return None
        o = urlsplit(s)
        t = o.scheme
        try:
            if t == "ss":
                return self._parse_ss(o)
            elif t == "trojan" or t == "trojan-go":
                return self._parse_trojan(o)
            elif t == "vmess":
                return self._parse_vmess(s)
            elif t == "vless":
                return self._parse_vless(o)
        except Exception as e:
            logger.error(e)
        return None

    def format_rule(self, lines: list):
        """
        对rule数据进行拼装
        """
        rules = []
        ip_rules = []
        for line in lines:
            if not line:
                continue
            s = line.strip()
            if s.startswith("DOMAIN") or s.startswith("SOURCE") or s.startswith("GEOIP"):
                rules.append(f"{s},%s")
            elif s.startswith("IP-CIDR"):
                rule = list(map(str.strip, s.split(",")))
                if rule[-1] == "no-resolve":
                    ip_rules.append("{},%s,{}".format(",".join(rule[:-1]), rule[-1]))
                else:
                    ip_rules.append(f"{s},%s")
        return rules, ip_rules

    def get_rule(self, files=[], rules=[]):
        all_rules = []
        if rules:
            all_rules.extend(rules)
        if files:
            for filepath in files:
                if not os.path.exists(filepath):
                    continue
                # 从下载的文件中读取配置项
                with open(filepath, "rt", encoding="utf-8") as f:
                    lines = f.readlines()
                    if lines:
                        all_rules.extend(lines)

        rule_list, ip_rule_list = self.format_rule(all_rules)
        rule_list = sorted(list(set(rule_list)))
        if ip_rule_list:
            rule_list.extend(sorted(list(set(ip_rule_list))))
        return rule_list

    def _clash_proxies(self, nodes):
        """
        解析clash格式节点数据
        """
        proxies = []
        for node in nodes:
            proxy = self._clash_decode(node)
            if proxy:
                proxies.append(proxy)
        return proxies

    def _clash_proxy_groups(self, proxies, cfg_groups):
        """
        clash 代理组
        """
        test_params = {"url": "http://www.gstatic.com/generate_204", "interval": 3600}

        groups = collections.defaultdict(list)
        nodeNames = [x["name"] for x in proxies if x.get("name")]

        addNodes = set()
        for p in nodeNames:
            upp = p.upper()
            if upp.find("TEST") >= 0 or p.find("测试") >= 0:
                addNodes.add(p)
                groups["测试线路"].append(p)
            elif upp.find("VIP") >= 0:
                addNodes.add(p)
                groups["VIP专线"].append(p)
            elif upp.find("IPLC") >= 0:
                addNodes.add(p)
                groups["IPLC专线"].append(p)
            elif upp.find("IEPL") >= 0:
                addNodes.add(p)
                groups["IPLC专线"].append(p)
            elif upp.find("VPS") >= 0:
                addNodes.add(p)
                groups["VPS组"].append(p)
        n = set(nodeNames) - addNodes
        nodeNames = [x for x in nodeNames if x in n]

        # 收集各国专线
        youhui_pattern = re.compile(r"0\.\d+?")
        duobei_pattern = re.compile(r"[x][2-9]|[x][1-9]\d+?|[2-9][xX]|[1-9]\d+?[xX]")
        for name, flag in self.countrys.items():
            addNodes = set()
            for p in nodeNames:
                if p.find(name) >= 0:
                    addNodes.add(p)
                    if youhui_pattern.search(p):
                        # groups[f"{flag}优惠"].append(p)
                        groups["优惠线路"].append(p)
                    elif duobei_pattern.search(p):
                        groups["多倍扣费"].append(p)
                    elif p.find("倍") >= 0:
                        groups["多倍扣费"].append(p)
                    # elif p.find("专线") >= 0:
                    #     groups[f"{flag}专线"].append(p)
                    else:
                        groups[flag].append(p)
            n = set(nodeNames) - addNodes
            nodeNames = [x for x in nodeNames if x in n]

        # 剩余解析不了的，全部归入其它
        groups["其它"] = list(nodeNames)

        allNodes = []
        autoNodes = []
        multiNodes = []
        proxyGroups = []
        for item in groups.keys():
            g = {}
            if item == "多倍扣费":
                g = {"name": f"💵{item}", "type": "select", "proxies": sorted(groups[item])}
                multiNodes.append(g["name"])
            elif item == "优惠线路":
                g = {"name": f"🎠{item}", "type": "select", "proxies": sorted(groups[item])}
                autoNodes.append(g["name"])
            elif item == "测试线路":
                g = {"name": "🪲测试组", "type": "select", "proxies": sorted(groups[item])}
                autoNodes.append(g["name"])
            elif item == "VIP专线":
                g = {"name": f"👑{item}", "type": "select", "proxies": sorted(groups[item])}
                autoNodes.append(g["name"])
            elif item == "IPLC专线":
                g = {"name": f"🎉{item}", "type": "select", "proxies": sorted(groups[item])}
                autoNodes.append(g["name"])
            elif item == "IEPL线路":
                g = {"name": f"🎉{item}", "type": "select", "proxies": sorted(groups[item])}
                autoNodes.append(g["name"])
            elif item == "VPS组":
                g = {"name": "🚀VPS组", "type": "select", "proxies": sorted(groups[item])}
                autoNodes.append(g["name"])
            elif item == "其它":
                g = {"name": item, "type": "select", "proxies": sorted(groups[item])}
            else:
                g = {"name": item, "type": "url-test", "proxies": sorted(groups[item]), **test_params}
                autoNodes.append(item)
            if g.get("proxies"):
                allNodes.extend(g["proxies"])
                proxyGroups.append(g)

        result = []
        exclude = ("DIRECT", "REJECT")
        for group in cfg_groups:
            if not group.get("proxies") or group["name"] in exclude:
                continue
            rec = group.copy()
            if rec.get("hosts"):
                rec.pop("hosts")
            if rec.get("rules"):
                rec.pop("rules")
            proxies = []
            for proxy in rec["proxies"]:
                if proxy == "@全部节点":
                    proxies.extend(allNodes)
                elif proxy == "@自动选择":
                    proxies.extend(autoNodes)
                elif proxy == "@节点组":
                    proxies.extend(autoNodes)
                    proxies.extend(multiNodes)
                else:
                    proxies.append(proxy)
            if not proxies:
                proxies.extend(allNodes)
            rec["proxies"] = proxies
            if rec["type"] == "url-test":
                rec.update(test_params)
            result.append(rec)
        result.extend(proxyGroups)
        return result

    def rules_local_netware(self):
        rules = "DOMAIN-SUFFIX,ip6-localhost,DIRECT DOMAIN-SUFFIX,ip6-loopback,DIRECT DOMAIN-SUFFIX,lan,DIRECT DOMAIN-SUFFIX,local,DIRECT DOMAIN-SUFFIX,localhost,DIRECT DOMAIN,instant.arubanetworks.com,DIRECT DOMAIN,setmeup.arubanetworks.com,DIRECT DOMAIN,router.asus.com,DIRECT DOMAIN-SUFFIX,hiwifi.com,DIRECT DOMAIN-SUFFIX,leike.cc,DIRECT DOMAIN-SUFFIX,miwifi.com,DIRECT DOMAIN-SUFFIX,my.router,DIRECT DOMAIN-SUFFIX,p.to,DIRECT DOMAIN-SUFFIX,peiluyou.com,DIRECT DOMAIN-SUFFIX,phicomm.me,DIRECT DOMAIN-SUFFIX,router.ctc,DIRECT DOMAIN-SUFFIX,routerlogin.com,DIRECT DOMAIN-SUFFIX,tendawifi.com,DIRECT DOMAIN-SUFFIX,zte.home,DIRECT DOMAIN-SUFFIX,tplogin.cn,DIRECT"
        return rules.split()

    def rules_suffix(self, proxyName):
        """
        后续添加的规则
        """
        return [
            "DOMAIN-KEYWORD,aria2,DIRECT",
            "DOMAIN-KEYWORD,xunlei,DIRECT",
            "DOMAIN-KEYWORD,yunpan,DIRECT",
            "DOMAIN-KEYWORD,Thunder,DIRECT",
            "DOMAIN-KEYWORD,XLLiveUD,DIRECT",
            "GEOIP,CN,DIRECT",
            f"MATCH,{proxyName}",
        ]

    def rule_config(self):
        """
        解析配置文件
        """
        cfg = self.config
        if cfg.get("proxy_groups"):
            hosts = []
            for x in cfg["proxy_groups"]:
                if x.get("hosts"):
                    hosts.extend(x["hosts"])
            utils.get_rule(hosts)
        return cfg

    def cleanNullNode(self, node):
        """
        清除字典中的空值
        """
        if not isinstance(node, dict):
            return node
        result = node.copy()
        for k in list(result.keys()):
            if isinstance(result[k], dict):
                result[k] = self.cleanNullNode(result[k])
            if not result[k]:
                result.pop(k)
        return result

    def download_rule_file(self) -> dict:
        """
        获取规则配置文件
        """
        hosts = []
        if self.config.get("proxy_groups"):
            for x in self.config["proxy_groups"]:
                if x.get("hosts"):
                    hosts.extend(x["hosts"])
        if "other_rules" in self.config:
            for rules in self.config["other_rules"]:
                if rules.get("hosts"):
                    hosts.extend(rules["hosts"])
                if rules.get("rule_set"):
                    hosts.extend(rules["rule_set"])

        return utils.get_rule(hosts)

    def init_headers(self, subinfo):
        """
        从源订阅网站获取订阅详情
        """
        if self._headers:
            return

        urlinfo = subinfo["urlinfo"]
        query = dict(parse_qsl(urlinfo.query))
        if not urlinfo.path == "/api/v1/client/subscribe":
            return

        query["flag"] = "clash"
        n = list(urlinfo[:])
        n[3] = "&".join([f"{k}={v}" for k, v in query.items()])
        new_url = urlunsplit(n)
        try:
            response = utils.get(new_url)
            headers = response["headers"]

            if "content-disposition" in headers:
                contentDisposition = headers["content-disposition"]
                filename = re.findall("filename\\u002A=[a-zA-z]+-[8]''(.+)", contentDisposition)
                if filename:
                    headers["filename"] = unquote(filename[0])

                    content_disposition_filename = filename[0]
                    if content_disposition_filename != headers["filename"]:
                        self._headers["content-disposition"] = (
                            f"attachment; filename*=utf-8''{content_disposition_filename}"
                        )
                    else:
                        self._headers["content-disposition"] = 'attachment; filename="{}"'.format(headers["filename"])

            if "subscription-userinfo" in headers:
                subscriptionUserinfo = headers["subscription-userinfo"]
                self._headers["subscription-userinfo"] = subscriptionUserinfo

            # 如果响应头中存在profile-update-interval字段，则配置文件自动更新间隔设置为对应的值，以小时为单位
            self._headers["profile-update-interval"] = headers.get("profile-update-interval") or 24

            # 如果响应头中存在profile-web-page-url字段，则在右键点击 profile 菜单中会显示Open web page选项，允许用户跳转到对应的门户首页
            self._headers["profile-web-page-url"] = headers.get("profile-web-page-url") or new_url
            try:
                self._headers["profile-web-page-url"].encode("latin-1")
            except Exception:
                self._headers["profile-web-page-url"] = quote(self._headers["profile-web-page-url"])

        except Exception:
            pass

    def convert(self, params, nodes):
        sites = []
        for node in nodes:
            if node:
                sites.extend(node["content"])
                self.init_headers(node)

        socks5_port = params.get("socks5_port") or 7890
        content = {
            "mixed-port": socks5_port,
            "allow-lan": True,
            "mode": "rule",
            "log-level": "info",
            "external-controller": "0.0.0.0:9090",
            "dns": {},
            "proxies": [],
        }
        for site in sites:
            proxie = site.to_clash()
            if proxie:
                content["proxies"].append(proxie)
        servers = {x["server"] for x in content["proxies"] if x.get("server")}
        svrips = {x for x in servers if utils.check_ip(x)}
        domains = {".".join(x.split(".")[-2:]) for x in servers - svrips if x}

        # 根据配置文件调整
        rule_files = self.download_rule_file()
        default_proxy = ""
        cfg_groups = []
        cfg_rules = [
            "IP-CIDR,198.18.0.1/16,REJECT,no-resolve",
            "GEOIP,private,DIRECT,no-resolve",
        ]
        for x in domains:
            cfg_rules.append(f"DOMAIN-SUFFIX,{x},DIRECT")
        for x in svrips:
            cfg_rules.append(f"IP-CIDR,{x}/32,DIRECT,no-resolve")
        cfg_rules.extend(self.rules_local_netware())
        cfg = self.rule_config()
        if cfg.get("ws-opts"):
            # 如果存在免流配置，就更新vmess 80端口且ws协议的免流参数
            for p in content["proxies"]:
                if p.get("ws-opts") and p["type"] == "vmess" and p["port"] == 80 and p.get("network") == "ws":
                    p["ws-opts"].update(cfg["ws-opts"])
                    p["ws-opts"] = self.cleanNullNode(p["ws-opts"])
            # result["proxies"] = json.loads(json.dumps(result["proxies"]))
        if cfg.get("proxy_groups"):
            cfg_groups = cfg["proxy_groups"]
            for x in cfg_groups:
                if not default_proxy:
                    default_proxy = x["name"]
                if x.get("default"):
                    default_proxy = x["name"]

                # 从文件或配置中获取规则
                files = []
                if x.get("hosts"):
                    pages = utils.get_rule(x["hosts"])
                    files = [page for page in pages if page]
                group_rules = x["rules"] if x.get("rules") else []
                rules = self.get_rule(files=files, rules=group_rules)
                if rules:
                    for r in rules:
                        cfg_rules.append(r % x["name"])
        # 载入自定义规则
        if "other_rules" in cfg:
            for rules in cfg["other_rules"]:
                outbound = default_proxy if rules["path"] == "PROXY" else rules["path"]
                add_rules = []
                if "rule_set" in rules:
                    for url in rules.get("rule_set"):
                        filename = os.path.basename(url)
                        if filename in rule_files:
                            add_rules.extend(rule_files[filename])
                if "rules" in rules:
                    add_rules.extend(rules["rules"])
                rule_list, ip_rule_list = self.format_rule(add_rules)
                for rule in rule_list:
                    cfg_rules.append(rule % outbound)
                for rule in ip_rule_list:
                    cfg_rules.append(rule % outbound)
        if cfg.get("dns"):
            content["dns"] = cfg["dns"]
        else:
            content.pop("dns")

        content["proxy-groups"] = self._clash_proxy_groups(content["proxies"], cfg_groups)

        # 唯一检查
        unique_check = set()
        unique_rules = []
        for rule in cfg_rules:
            if rule in unique_check:
                continue
            unique_check.add(rule)
            unique_rules.append(rule)
        content["rules"] = unique_rules
        content["rules"].extend(self.rules_suffix(default_proxy))

        return {"headers": self._headers, "body": content, "mimetype": "application/yaml"}
