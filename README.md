# openwrt-tiny
openwrt x86_64旁路由专用，仅保留ZeroTier WireGuard ttyd lucky ShellCrash，有关openwrt的问题不要问我，我也不懂，这是自用的，通过PVE或EXSI运行，开发它的目的仅仅是能快速的部署好我需要的旁路由。

- IP地址：192.168.5.100
- 用户名：root
- 密码：无密码
- 固件下载: [Releases](https://github.com/cgistar/openwrt-tiny/releases)

## ShellCrash 离线配置
已经预先将安装文件保存到了`/etc/ShellCrash`，但还需要进行配置，进入系统-TTYD终端后，在里面运行：
```sh
sh /usr/share/sub/install_sc.sh
```

### 自行安装配置
```sh
source /etc/ShellCrash/init.sh
```

### 预安装项目：
1. Sing-Box-Puer内核
2. yacd魔改面板
3. 代理模式为：Tproxy模式
4. DNS配置来自 [sing-box PuerNya 版内核配置 DNS 不泄露教程-ruleset 方案](https://github.com/DustinWin/clash_singbox-tutorials/blob/main/%E6%95%99%E7%A8%8B%E5%90%88%E9%9B%86/sing-box/%E8%BF%9B%E9%98%B6%E7%AF%87/sing-box%20PuerNya%20%E7%89%88%E5%86%85%E6%A0%B8%E9%85%8D%E7%BD%AE%20DNS%20%E4%B8%8D%E6%B3%84%E9%9C%B2%E6%95%99%E7%A8%8B-ruleset%20%E6%96%B9%E6%A1%88.md)，做了部分修改
5. 去除了fake-ip有需要的自己加入

## 订阅转换
ShellCrash订阅配置非常麻烦，提供的线上转换功能也不符合我的要求，所以自己写了一个转换程序，同时提供订阅WEB服务，**我只测试了自己买的订阅，可能这个方式不适合你**。

支持转换的订阅类型：
- clash
- clash.meta
- sing-box
- surge

### 直接 ShellCrash 转换订阅链接（推荐）
```sh
# 直接运行，系统会自动查找 ShellCrash 的订阅链接进行订阅转换
/usr/share/sub/sub

# 不使用配置项中的订阅链接，通过参数进行调用
/usr/share/sub/sub -t singbox -url http://aa.aa.com/api/v1/client/subscribe?token=feed5 http://bb.bb.com/api/v1/client/subscribe?token=dsfd
```
- 源代码在sub目录下，安装依赖`pip install -r requirements.txt`
- 支持多个订阅合并，空格分隔
- 修改 /usr/share/sub/setting.json 定制化自己的需求
- 傻瓜化运行，只要提供订阅链接，将自动将配置文件保存到ShellCrash安装文件夹下
- $CRASHDIR/jsons/dns.json 或 $CRASHDIR/yamls/user.yaml，没有会自动生成，dns_nameserver、dns_fallback需要设置为null
- clash 与 meta 核心互相变更时，请自行删除$CRASHDIR/yamls/user.yaml，clash不支持rule-set
- 因为clash支持的协议较少，部分订阅将因为没有站点而转换出来的配置不能启动

### 订阅后台服务运行
```sh
nohup /usr/share/sub/sub -web -p=25500 2>&1 >>/dev/null &
```
它不仅仅只能ShellCrash使用，通过参数target进行识别: singbox clash clash.meta surge
```
http://127.0.0.1:25500?url=http://aa.aa.com/api/v1/client/subscribe?token=feed5&target=clash.meta
```

## 固件来源：

lean固件源码地址：https://github.com/coolsnowwolf/lede

插件引用：[luci-app-lucky](https://github.com/gdy666/luci-app-lucky.git) [luci-theme-opentomcat](https://github.com/WukongMaster/luci-theme-opentomcat.git) [ShellCrash](https://github.com/juewuy/ShellCrash)

由衷感谢所有为openwrt无私奉献的大佬们。
