# -*- coding: utf-8 -*-

import base64
import json
from urllib.parse import parse_qsl, unquote, urlsplit


def b64decode(text) -> str:
    if isinstance(text, str):
        encode_bytes = text.encode()
    elif isinstance(text, bytes):
        encode_bytes = text
    add = 4 - (len(encode_bytes) % 4)
    if add:
        encode_bytes += b"=" * add
    return base64.b64decode(encode_bytes).decode("utf-8")


class XRay:
    def __init__(self) -> None:
        self.init_value()

    def init_value(self):
        self._scheme = ""
        self._name = ""
        self._address = ""
        self._port = 443
        self._udp = True
        self._network = None
        self._sni = None
        self._serviceName = None
        self._fingerprint = "chrome"
        self._user_id = ""
        # 当协议为 VMess 时，对应配置文件出站中 settings.security，可选值为 auto / aes-128-gcm / chacha20-poly1305 / none
        self._encryption = "none"
        # 设定底层传输所使用的 TLS 类型。当前可选值有 none，tls 和 reality
        self._security = "none"
        self._flow = ""
        self._public_key = None
        self._short_id = None
        self._streamSettings = {}
        self._tlsSettings = {}
        self._tcpSettings = {}
        self._kcpSettings = {}
        self._wsSettings = {}
        self._httpSettings = {}
        self._quicSettings = {}
        self._grpcSettings = {}
        self._realitySettings = {}

    @property
    def scheme(self):
        return self._scheme

    @scheme.setter
    def scheme(self, scheme):
        self._scheme = scheme

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, address):
        self._address = address

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, port):
        self._port = port

    @property
    def udp(self):
        return self._udp

    @udp.setter
    def udp(self, udp):
        self._udp = udp

    @property
    def network(self):
        return self._network

    @network.setter
    def network(self, network):
        self._network = network

    @property
    def sni(self):
        return self._sni

    @sni.setter
    def sni(self, sni):
        self._sni = sni

    @property
    def serviceName(self):
        return self._serviceName

    @serviceName.setter
    def serviceName(self, serviceName):
        self._serviceName = serviceName

    @property
    def fingerprint(self):
        return self._fingerprint

    @fingerprint.setter
    def fingerprint(self, fingerprint):
        self._fingerprint = fingerprint

    @property
    def user_id(self):
        return self._user_id

    @user_id.setter
    def user_id(self, user_id):
        self._user_id = user_id

    @property
    def encryption(self):
        return self._encryption

    @encryption.setter
    def encryption(self, encryption):
        self._encryption = encryption

    @property
    def security(self):
        return self._security

    @security.setter
    def security(self, security):
        self._security = security

    @property
    def flow(self):
        return self._flow

    @flow.setter
    def flow(self, flow):
        self._flow = flow

    @property
    def public_key(self):
        return self._public_key

    @public_key.setter
    def public_key(self, public_key):
        self._public_key = public_key

    @property
    def short_id(self):
        return self._short_id

    @short_id.setter
    def short_id(self, short_id):
        self._short_id = short_id

    @property
    def streamSettings(self):
        return self._streamSettings

    @streamSettings.setter
    def streamSettings(self, streamSettings):
        self._streamSettings = streamSettings

    @property
    def tlsSettings(self):
        return self._tlsSettings

    @tlsSettings.setter
    def tlsSettings(self, tlsSettings):
        self._tlsSettings = tlsSettings

    @property
    def tcpSettings(self):
        return self._tcpSettings

    @tcpSettings.setter
    def tcpSettings(self, tcpSettings):
        self._tcpSettings = tcpSettings

    @property
    def wsSettings(self):
        return self._wsSettings

    @wsSettings.setter
    def wsSettings(self, wsSettings):
        self._wsSettings = wsSettings

    @property
    def httpSettings(self):
        return self._httpSettings

    @httpSettings.setter
    def httpSettings(self, httpSettings):
        self._httpSettings = httpSettings

    @property
    def quicSettings(self):
        return self._quicSettings

    @quicSettings.setter
    def quicSettings(self, quicSettings):
        self._quicSettings = quicSettings

    @property
    def grpcSettings(self):
        return self._grpcSettings

    @grpcSettings.setter
    def grpcSettings(self, grpcSettings):
        self._grpcSettings = grpcSettings

    @property
    def realitySettings(self):
        return self._realitySettings

    @realitySettings.setter
    def realitySettings(self, realitySettings):
        self._realitySettings = realitySettings

    def parse_vmess_v2(self, url):
        info = json.loads(b64decode(url[8:].strip()))
        self.scheme = "vmess"
        self.name = info["ps"]
        self.address = info["add"]
        self.port = info.get("port") or "443"
        self.port = int(self.port)
        self._udp = True
        self.user_id = info["id"]
        self.encryption = info.get("scy") or "auto"
        self.serviceName = info.get("serviceName") or info["add"]
        if info.get("tls"):
            self.security = "tls"

        # tcp、kcp、ws、http、quic、grpc
        self.network = info.get("net")
        if self.network == "ws":
            self.wsSettings = {"path": info.get("path") or "/"}
            if info.get("host"):
                self.wsSettings["headers"] = {"Host": info["host"]}
        elif self.network == "h2":
            self.httpSettings = {
                "path": info.get("path") or "/",
            }
            if info.get("host"):
                self.httpSettings["host"] = list(map(str.strip, info["host"].split(",")))
        elif self.network == "http":
            self.httpSettings = {
                "method": "GET",
                "path": info.get("path") or "/",
                "headers": {"Connection": ["keep-alive"]},
            }
        elif self.network == "quic":
            # security 可选值有 none / aes-128-gcm / chacha20-poly1305
            self.quicSettings = {"security": info.get("quicSecurity") or "none"}
            if self.quicSettings["security"] != "none":
                self.quicSettings["key"] = info["key"]
            if info.get("headerType"):
                self.quicSettings["header"] = {"type": info["headerType"]}
        elif self.network == "grpc":
            # multiMode 可选值有 gun / multi / guna
            self.grpcSettings = {"grpc-service-name": self.serviceName}

    def parse_vless(self, url):
        """
        vless://bc8bf32e-ce01-4345-8e06-8d8cb03634e7@108.181.23.71:443?type=tcp&encryption=none&security=reality&flow=xtls-rprx-vision&sni=disc501.prod.do.dsp.mp.microsoft.com&pbk=tJX7QSzAR3XfL3mMPCmk3kuysE4kffHZuvgx_1ZKWgU&sid=b403059469ffb013&headerType=none&fp=chrome#🇺🇸美国洛杉矶02-0.1倍

        # vless://bc8bf32e-ce01-4345-8e06-8d8cb03634e7@178.173.236.226:443?type=tcp&encryption=none&security=tls&flow=xtls-rprx-vision&sni=9f6a39dd-8a37-47c1-a145-fe9d49f06de2.hnkkt.com&headerType=none&host=&path=&fp=safari#%F0%9F%87%AD%F0%9F%87%B0%E9%A6%99%E6%B8%AFHKT2%20%7C%20%E9%AB%98%E9%80%9F%E4%B8%93%E7%BA%BF
        """
        query = dict(parse_qsl(url.query))
        path = query.get("path") or "%2F"
        path = unquote(path)
        self.name = unquote(url.fragment)
        self.address = url.hostname
        self.port = url.port
        self.scheme = url.scheme
        self.user_id = url.username
        if query.get("fp"):
            self.fingerprint = query["fp"]
        if query.get("sni"):
            self.sni = query["sni"]
        self.security = query.get("security")
        self.encryption = query.get("encryption") or "none"
        self.serviceName = query.get("serviceName") or self.sni or self.address
        self.flow = query.get("flow")
        self.network = query.get("type") or "http"
        self.public_key = query.get("pbk")
        self.short_id = query.get("sid")

        if self.security == "xtls":
            self.flow = query.get("flow") or "xtls-rprx-direct"
        elif self.security == "reality":
            self.flow = query.get("flow") or "xtls-rprx-vision"
        elif self.security == "tls":
            self.udp = True
            if self.network == "ws":
                self.wsSettings = {"path": path}
                if query.get("host"):
                    self.wsSettings["headers"] = {"Host": unquote(query["host"])}
            elif self.network == "http":
                self.httpSettings = {
                    "path": path,
                }
                if query.get("host"):
                    self.httpSettings["host"] = list(map(unquote, query["host"].split(",")))
            elif self.network == "grpc":
                self.grpcSettings = {
                    "serviceName": self.serviceName,
                    "multiMode": query.get("mode") or "gun",
                    "idle_timeout": 60,
                    "health_check_timeout": 20,
                }
        if self.flow == "xtls-rprx-vision":
            self.serviceName = "testingcf.jsdelivr.net"

    def parse_from_clash(self, subinfo):
        # { network: ws, ws-opts: { path: /, headers: { Host: gw.alicdn.com } }, ws-path: /, ws-headers: { Host: gw.alicdn.com } }
        # subinfo = json.loads(sub)
        self.name = unquote(subinfo["name"])
        self.scheme = subinfo["type"]
        self.address = subinfo["server"]
        self.port = subinfo["port"]
        self.user_id = subinfo["uuid"]
        self.encryption = subinfo["cipher"]
        self.udp = subinfo.get("udp") or True
        self.network = subinfo["network"]
        if subinfo.get("tls"):
            self.security = "tls"
        if subinfo.get("ws-opts"):
            self.wsSettings = subinfo["ws-opts"]
        if subinfo.get("h2-opts"):
            self.httpSettings = subinfo["h2-opts"]
        if subinfo.get("http-opts"):
            self.httpSettings = subinfo["http-opts"]
        if subinfo.get("grpc-opts"):
            self.grpcSettings = subinfo["grpc-opts"]

    def to_clash(self):
        if self.scheme == "vless":
            return {}
        result = {
            "name": self.name,
            "type": self.scheme,
            "server": self.address,
            "port": self.port,
            "uuid": self.user_id,
            "alterId": 0,
            "cipher": self.encryption,
            "udp": self.udp,
            "network": self.network,
        }
        if self.security == "tls":
            result["tls"] = True
        if self.network == "ws":
            result["ws-opts"] = self.wsSettings
            # result["ws-opts"]["max-early-data"] = 2048
            # result["ws-opts"]["early-data-header-name"] = "Sec-WebSocket-Protocol"
            result["ws-path"] = self.wsSettings["path"]
            if self.wsSettings.get("headers"):
                result["ws-headers"] = {"Host": self.wsSettings["headers"]["Host"]}
        elif self.network == "h2":
            result["h2-opts"] = self.httpSettings
        elif self.network == "http":
            result["http-opts"] = self.httpSettings
        elif self.network == "grpc":
            result["grpc-opts"] = self.grpcSettings
        return result

    def to_mihomo(self):
        result = {
            "name": self.name,
            "type": self.scheme,
            "server": self.address,
            "port": self.port,
            "uuid": self.user_id,
            "alterId": 0,
            "cipher": self.encryption,
            "udp": self.udp,
            "tls": False,
            "skip-cert-verify": True,
            "network": self.network,
            "client-fingerprint": self.fingerprint,
        }
        if self.security == "tls":
            result["tls"] = True
            result["skip-cert-verify"] = False
        if self.flow == "xtls-rprx-vision":
            result["servername"] = self.serviceName
            result["flow"] = self.flow
            if self.public_key:
                result["reality-opts"] = {
                    "public-key": self.public_key,
                    "short-id": self.short_id,
                }
        if self.network == "ws":
            result["ws-opts"] = self.wsSettings
        elif self.network == "h2":
            result["h2-opts"] = self.httpSettings
        elif self.network == "http":
            result["http-opts"] = self.httpSettings
        elif self.network == "grpc":
            result["grpc-opts"] = {"grpc-service-name": self.serviceName}
            if self.flow == "xtls-rprx-vision":
                result["grpc-opts"]["grpc-service-name"] = "grpc"
        return result

    def to_surge(self):
        if self.scheme == "vless":
            return {}
        result = [f"{self.name}={self.scheme},{self.address},{self.port}"]
        result.append(f"username={self.user_id}")
        if self.encryption in ("aes-128-gcm", "chacha20-poly1305"):
            result.append(f"encrypt-method={self.encryption}")
        result.append("vmess-aead=true")
        if self.security == "tls":
            result.append("tls=true")
        else:
            result.append("skip-cert-verify=true")
        if self.network == "ws":
            result.append("ws=true")
            result.append("ws-path={}".format(self.wsSettings.get("path") or "/"))
            if self.wsSettings.get("headers"):
                result.append("ws-headers=Host:{}".format(self.wsSettings["headers"]["Host"]))
        result.append("tfo=true")
        result.append("udp-relay=true")

        return ",".join(result)

    def to_singbox(self):
        result = {}
        if self.scheme == "vmess":
            result = {
                "tag": self.name,
                "type": self.scheme,
                "server": self.address,
                "server_port": self.port,
                "uuid": self.user_id,
                "alter_id": 0,
                "security": "auto",
                "packet_encoding": "packetaddr",
            }
            if self.encryption in ("aes-128-gcm", "chacha20-poly1305"):
                result["security"] = self.encryption
            if self.security == "tls":
                result["tls"] = {
                    "enabled": True,
                    "server_name": self.sni or self.address,
                    "utls": {"enabled": True, "fingerprint": self.fingerprint},
                }
            if self.network == "ws":
                result["transport"] = {
                    "type": self.network,
                    "path": self.wsSettings.get("path") or "/",
                }
                if self.wsSettings.get("headers"):
                    result["transport"]["headers"] = {"Host": self.wsSettings["headers"]["Host"]}
        elif self.scheme == "vless":
            result = {
                "tag": self.name,
                "type": self.scheme,
                "server": self.address,
                "server_port": self.port,
                "uuid": self.user_id,
                "packet_encoding": "xudp",
            }
            if self.flow == "xtls-rprx-vision":
                result["flow"] = self.flow
                result["tls"] = {
                    "enabled": True,
                    "insecure": False,
                    "server_name": self.sni,
                    "utls": {"enabled": True, "fingerprint": self.fingerprint},
                }
                if self.public_key and self.short_id:
                    result["tls"]["reality"] = {
                        "enabled": True,
                        "public_key": self.public_key,
                        "short_id": self.short_id,
                    }
        return result

    @staticmethod
    def parse_url(url):
        vless = XRay()
        if isinstance(url, str):
            if url.find("?") >= 0:
                url_args = urlsplit(url)
                vless.parse_vless(url_args)
            else:
                vless.parse_vmess_v2(url)
        elif isinstance(url, dict):
            vless.parse_from_clash(url)
        return vless


class Trojan:
    def __init__(self) -> None:
        self.init_value()

    def init_value(self):
        self._scheme = "trojan"
        self._name = ""
        self._address = ""
        self._remote_addr = ""
        self._remote_port = 443
        self._password = ""
        self._allowInsecure = True
        self._udp = True
        self._sni = None
        self._type = None
        self._host = None
        self._path = None
        self._encryption = None
        self._serviceName = None

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, address):
        self._address = address

    @property
    def remote_addr(self):
        return self._remote_addr

    @remote_addr.setter
    def remote_addr(self, remote_addr):
        self._remote_addr = remote_addr
        self._address = remote_addr

    @property
    def remote_port(self):
        return self._remote_port

    @remote_port.setter
    def remote_port(self, remote_port):
        self._remote_port = remote_port

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, password):
        self._password = password

    @property
    def allowInsecure(self):
        return self._allowInsecure

    @allowInsecure.setter
    def allowInsecure(self, allowInsecure):
        self._allowInsecure = allowInsecure

    @property
    def udp(self):
        return self._udp

    @udp.setter
    def udp(self, udp):
        self._udp = udp

    @property
    def sni(self):
        return self._sni

    @sni.setter
    def sni(self, sni):
        self._sni = sni

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, type):
        self._type = type

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, host):
        self._host = host

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, path):
        self._path = path

    @property
    def encryption(self):
        return self._encryption

    @encryption.setter
    def encryption(self, encryption):
        self._encryption = encryption

    @property
    def serviceName(self):
        return self._serviceName

    @serviceName.setter
    def serviceName(self, serviceName):
        self._serviceName = serviceName

    def parse_subscribe(self, url):
        # trojan://bc8bf32e-ce01-4345-8e06-8d8cb03634e7@209.46.30.11:443?allowInsecure=0&peer=2jp2.pqjc.buzz&sni=2jp2.pqjc.buzz&type=ws&host=2jp2.pqjc.buzz&path=/pq/jp2#%F0%9F%87%AF%F0%9F%87%B5%E6%97%A5%E6%9C%AC%E9%AB%98%E9%80%9F02-0.1%E5%80%8D
        query = dict(parse_qsl(url.query))
        self.name = unquote(url.fragment)
        self.remote_addr = url.hostname
        self.remote_port = url.port
        self.password = url.username
        self.sni = query.get("sni") or query.get("peer")
        if self.sni:
            self.sni = unquote(self.sni)
            self.allowInsecure = False
        if query.get("allowInsecure"):
            self.allowInsecure = query["allowInsecure"] in ["1", 1, "true"]
        if query.get("type"):
            self.type = query["type"]
        if query.get("path"):
            self.path = unquote(query["path"])
        if query.get("host"):
            self.host = unquote(query["host"])
        if query.get("encryption"):
            self.encryption = unquote(query["encryption"])
        if query.get("serviceName"):
            self.serviceName = unquote(query["serviceName"])

    def parse_from_clash(self, subinfo):
        self.name = unquote(subinfo["name"])
        self.remote_addr = subinfo["server"]
        self.remote_port = subinfo["port"]
        self.password = subinfo["password"]
        self.type = subinfo.get("network")
        self.sni = subinfo.get("sni")
        if subinfo.get("skip-cert-verify"):
            self.allowInsecure = True
        if subinfo.get("ws-opts"):
            self.path = subinfo["ws-opts"].get("path")
            if subinfo["ws-opts"].get("headers"):
                self.host = subinfo["ws-opts"]["headers"].get("Host")
        if subinfo.get("grpc-opts"):
            self.serviceName = subinfo["grpc-opts"].get("grpc-service-name")

    def to_clash(self):
        result = {
            "name": self.name,
            "type": "trojan",
            "server": self.remote_addr,
            "port": self.remote_port,
            "password": self.password,
            "udp": self.udp,
        }
        if self.sni:
            result["sni"] = self.sni
        if self.allowInsecure:
            result["skip-cert-verify"] = True
        if self.type == "ws":
            result["network"] = self.type
            ws_opts = {}
            if self.path:
                ws_opts["path"] = self.path
            if self.host:
                ws_opts["headers"] = {"Host": self.host}
            if ws_opts:
                result["ws-opts"] = ws_opts
        elif self.type == "grpc":
            result["network"] = self.type
            result["grpc-opts"]["grpc-service-name"] = self.serviceName or self.remote_addr
        return result

    def to_mihomo(self):
        result = {
            "name": self.name,
            "type": "trojan",
            "server": self.remote_addr,
            "port": self.remote_port,
            "password": self.password,
            "udp": self.udp,
        }
        if self.sni:
            result["sni"] = self.sni
        if self.allowInsecure:
            result["skip-cert-verify"] = True
        if self.type == "ws":
            result["network"] = self.type
            ws_opts = {}
            if self.path:
                ws_opts["path"] = self.path
            if self.host:
                ws_opts["headers"] = {"Host": self.host}
            if ws_opts:
                result["ws-opts"] = ws_opts
        elif self.type == "grpc":
            result["network"] = self.type
            result["grpc-opts"]["grpc-service-name"] = self.serviceName or self.remote_addr
        return result

    def to_surge(self):
        result = [f"{self.name}=trojan,{self.remote_addr},{self.remote_port}"]
        result.append(f"password={self.password}")
        if self.sni:
            result.append(f"sni={self.sni}")
            result.append("tls=true")
        if self.allowInsecure:
            result.append("skip-cert-verify=true")
        if self.type == "ws":
            result.append("ws=true")
            if self.path:
                result.append(f"ws-path={self.path}")
            if self.host:
                result.append(f"ws-headers=Host:{self.host}")
        result.append("tfo=true")
        result.append("udp-relay=true")

        return ",".join(result)

    def to_singbox(self):
        result = {
            "tag": self.name,
            "type": "trojan",
            "server": self.remote_addr,
            "server_port": self.remote_port,
            "password": self.password,
        }
        if self.sni:
            result["tls"] = {"enabled": True, "insecure": self.allowInsecure, "server_name": self.sni}
        if self.type == "ws":
            transport = {
                "type": self.type,
                "path": self.path,
                "headers": {"Host": self.host},
                # "max_early_data": 2048,
                # "early_data_header_name": "Sec-WebSocket-Protocol",
            }
            result["transport"] = transport
        return result

    @staticmethod
    def parse_url(url: str):
        tj = Trojan()
        if isinstance(url, str):
            url_args = urlsplit(url)
            tj.parse_subscribe(url_args)
        elif isinstance(url, dict):
            tj.parse_from_clash(url)
        return tj


class Shadowsocks:
    def __init__(self) -> None:
        self.init_value()

    def init_value(self):
        self._scheme = "ss"
        self._name = ""
        self._address = ""
        self._server = ""
        self._server_port = 443
        self._method = ""
        self._password = ""
        self._udp = True
        self._timeout = 300
        self._plugin = None
        # mode: websocket host: xxx.xxx.xxx path: "/s" tls: true skip-cert-verify: true mux: true
        self._plugin_opts = {}

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, address):
        self._address = address

    @property
    def server(self):
        return self._server

    @server.setter
    def server(self, server):
        self._server = server
        self._address = server

    @property
    def server_port(self):
        return self._server_port

    @server_port.setter
    def server_port(self, server_port):
        self._server_port = server_port

    @property
    def method(self):
        return self._method

    @method.setter
    def method(self, method):
        self._method = method

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, password):
        self._password = password

    @property
    def udp(self):
        return self._udp

    @udp.setter
    def udp(self, udp):
        self._udp = udp

    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, timeout):
        self._timeout = timeout

    @property
    def plugin(self):
        return self._plugin

    @plugin.setter
    def plugin(self, plugin):
        self._plugin = plugin

    @property
    def plugin_opts(self):
        return self._plugin_opts

    @plugin_opts.setter
    def plugin_opts(self, plugin_opts):
        self._plugin_opts = plugin_opts

    def parse_sip002(self, url):
        # ss://YWVzLTI1Ni1nY206cEFzc1dvcmQ@www.example.com:10086/?plugin=v2ray-plugin_windows_amd64%3btls%3bhost%3dwww.example.com#example_name
        query = dict(parse_qsl(url.query))
        self.name = unquote(url.fragment)
        self.server = url.hostname
        self.server_port = url.port
        userpass = b64decode(url.username).split(":")
        self.method = userpass[0]
        self.password = userpass[1]
        if query.get("plugin"):
            plugin_str = unquote(query["plugin"])
            plugin = list(map(str.strip, plugin_str.split(";")))
            if len(plugin) > 1:
                self.plugin = plugin.pop(0)
                new_opts = {}
                for opt in plugin:
                    params = opt.split("=")
                    if len(params) == 1:
                        new_opts[params[0]] = True
                    elif len(params) == 2:
                        new_opts[params[0]] = params[1]
                self.plugin_opts = new_opts

    def parse_from_clash(self, subinfo):
        # subinfo = json.loads(sub)
        self.name = unquote(subinfo["name"])
        self.server = subinfo["server"]
        self.server_port = subinfo["port"]
        self.method = subinfo["cipher"]
        self.password = subinfo["password"]
        self.udp = subinfo["udp"]
        if subinfo.get("plugin"):
            self.plugin = subinfo["plugin"]
            if subinfo.get("plugin-opts"):
                self.plugin_opts = subinfo["plugin-opts"]

    def to_clash(self):
        result = {
            "name": self.name,
            "type": "ss",
            "server": self.server,
            "port": self.server_port,
            "cipher": self.method,
            "password": self.password,
            "udp": self.udp,
        }
        if self.plugin:
            result["plugin"] = self.plugin
            result["plugin-opts"] = self.plugin_opts
        return result

    def to_mihomo(self):
        result = {
            "name": self.name,
            "type": "ss",
            "server": self.server,
            "port": self.server_port,
            "cipher": self.method,
            "password": self.password,
            "udp": self.udp,
        }
        if self.plugin:
            result["plugin"] = self.plugin
            result["plugin-opts"] = self.plugin_opts
        return result

    def to_surge(self):
        result = [f"{self.name}=ss,{self.server},{self.server_port}"]
        result.append(f"encrypt-method={self.method}")
        result.append(f"password={self.password}")
        result.append("tfo=true")
        result.append("udp-relay=true")
        return ",".join(result)

    def to_singbox(self):
        result = {
            "tag": self.name,
            "type": "shadowsocks",
            "server": self.server,
            "server_port": self.server_port,
            "method": self.method,
            "password": self.password,
        }

        if self.plugin:
            result["plugin"] = self.plugin
            result["plugin-opts"] = self.plugin_opts

        return result

    @staticmethod
    def parse_url(url):
        ss = Shadowsocks()
        if isinstance(url, str):
            url_args = urlsplit(url)
            ss.parse_sip002(url_args)
        elif isinstance(url, dict):
            ss.parse_from_clash(url)
        return ss


class Hysteria2:
    def __init__(self) -> None:
        self.init_value()

    def init_value(self):
        self._scheme = "hysteria2"
        self._name = ""
        self._address = ""
        self._port = 443
        self._password = ""
        self._sni = None
        self._insecure = False

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, address):
        self._address = address

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, port):
        self._port = port

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, password):
        self._password = password

    @property
    def sni(self):
        return self._sni

    @sni.setter
    def sni(self, sni):
        self._sni = sni

    @property
    def insecure(self):
        return self._insecure

    @insecure.setter
    def insecure(self, insecure):
        self._insecure = insecure

    def parse_subscribe(self, url):
        query = dict(parse_qsl(url.query))
        self.name = unquote(url.fragment)
        self.address = url.hostname
        self.port = url.port
        self.password = url.username
        self.sni = url.hostname
        if query.get("sni"):
            self.sni = unquote(query["sni"])
        if query.get("insecure"):
            self.insecure = query["insecure"] in ["1", 1, "true"]

    def to_clash(self):
        return {}

    def to_mihomo(self):
        node = {
            "name": self.name,
            "server": self.address,
            "port": self.port,
            "type": "hysteria2",
            "password": self.password,
        }
        if self.sni:
            node["sni"] = self.sni
        if self.insecure:
            node["skip-cert-verify"] = self.insecure
        return node

    def to_surge(self):
        result = [f"{self.name}=hysteria,{self.address},{self.port}"]
        result.append(f"password={self.password}")
        if self.sni:
            result.append(f"sni={self.sni}")
            result.append("tls=true")
        if self.insecure:
            result.append("skip-cert-verify=true")
        result.append("download-bandwidth=300")
        result.append("tfo=true")
        result.append("udp-relay=true")

        # return ",".join(result)
        return {}

    def to_singbox(self):
        result = {
            "tag": self.name,
            "type": "hysteria2",
            "server": self.address,
            "server_port": self.port,
            "password": self.password,
            "tls": {"enabled": True, "insecure": self.insecure, "server_name": self.sni},
        }
        return result

    @staticmethod
    def parse_url(url: str):
        hy2 = Hysteria2()
        url_args = urlsplit(url)
        hy2.parse_subscribe(url_args)
        return hy2
