# openwrt-tiny
openwrt x86_64旁路由专用，仅保留ZeroTier WireGuard ttyd lucky ShellCrash

- IP地址：192.168.5.100
- 用户名：root
- 密码：无密码
- 固件下载: [Releases](https://github.com/cgistar/openwrt-tiny/releases)

## ShellCrash 安装
安装文件在`/opt/ShellCrash`下，进入系统-TTYD终端，在里面运行：
```sh
sh /usr/share/sub/install_sc.sh
```
按需选择进行安装

### 预安装项目：
1. Sing-Box-Puer内核
2. yacd魔改面板
3. 代理模式为：Tproxy模式
4. DNS配置来自 [sing-box PuerNya 版内核配置 DNS 不泄露教程-ruleset 方案](https://github.com/DustinWin/clash_singbox-tutorials/blob/main/%E6%95%99%E7%A8%8B%E5%90%88%E9%9B%86/sing-box/%E8%BF%9B%E9%98%B6%E7%AF%87/sing-box%20PuerNya%20%E7%89%88%E5%86%85%E6%A0%B8%E9%85%8D%E7%BD%AE%20DNS%20%E4%B8%8D%E6%B3%84%E9%9C%B2%E6%95%99%E7%A8%8B-ruleset%20%E6%96%B9%E6%A1%88.md)，做了部分修改
5. 去除了fake-ip有需要的自己加入

## ShellCrash 订阅转换
开发了与ShellCrash兼容的订阅WEB服务，提供直接转换订阅、提供127.0.0.1:25500的WEB订阅转换服务
### 直接转换订阅链接（推荐）
```sh
/usr/share/sub/sub.py -url http://aa.aa.com/api/v1/client/subscribe?token=feed5  http://bb.bb.com/api/v1/client/subscribe?token=dsfd
```
- 需要python3环境（openwrt已自带），自己建立环境需要安装一些依赖`pip install -r requirements.txt`
- 支持多个订阅合并
- 修改 /usr/share/sub/config.json 可以自己定制化
- 傻瓜化运行，只要提供订阅链接，将自动将配置文件保存到ShellCrash安装文件夹下，同时也会生成DNS配置
- clash 与 meta 核心互相变更时，请自行删除$CRASHDIR/yamls/user.yaml，clash不支持rule-set
- 因为clash支持的协议较少，部分订阅将因为没有站点而转换出来的配置不能启动

### WEB调用方法
```sh
nohup python3 /usr/share/sub/sub.py -web -p=25500 2>&1 >>/dev/null &
```

## DNS配置文件在$CRASHDIR/jsons/dns.json
按需修改
```json
{
  "dns": {
    "servers": [
      { "tag": "dns_refused", "address": "rcode://success" },
      { "tag": "dns_proxy", "address": "https://1.1.1.1/dns-query" },
      { "tag": "dns_direct", "address": "https://223.5.5.5/dns-query", "detour": "DIRECT" }
    ],
    "rules": [
      { "domain_suffix": "in-addr.arpa", "server": "dns_refused", "disable_cache": true },
      { "outbound": "any", "server": "dns_direct" },
      { "clash_mode": "direct", "server": "dns_direct" },
      { "clash_mode": "global", "rewrite_ttl": 0, "disable_cache": true, "server": "dns_proxy" },
      { "rule_set": ["geosite-category-ads-all"], "server": "dns_refused" },
      { "rule_set": ["geosite-cn"], "query_type": ["A", "AAAA"], "server": "dns_direct" },
      { "rule_set": ["proxy"], "query_type": ["A", "AAAA"], "rewrite_ttl": 0, "disable_cache": true, "server": "dns_proxy" }
    ],
    "final": "dns_proxy",
    "strategy": "prefer_ipv4",
    "independent_cache": true,
    "reverse_mapping": true
  }
}
```

自己配置好rule_set需要的文件
```json
{
  "route": {
    "rule_set": [
      {
        "tag": "geosite-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"
      },
      {
        "tag": "geosite-category-ads-all",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs"
      },
      {
        "tag": "proxy",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/DustinWin/ruleset_geodata/sing-box-ruleset/proxy.srs"
      }
    ]
  }
}
```
