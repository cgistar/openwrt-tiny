#!/bin/ash

setsingboxp(){
    if [ -f $CRASHDIR/CrashCore.tar.gz ]; then
        tar -zxf $CRASHDIR/CrashCore.tar.gz -C /tmp/
        core_v=$(/tmp/CrashCore version 2>/dev/null | grep version | awk '{print $3}')
        rm -rf /tmp/CrashCore

        setconfig crashcore singboxp
        setconfig core_v $core_v
        rm -rf ${CRASHDIR}/Country.mmdb
        rm -rf ${CRASHDIR}/GeoSite.dat
        setconfig Country_v
        setconfig cn_mini_v
        setconfig geosite_v

        TMPDIR='/tmp/ShellCrash'
        BINDIR=${CRASHDIR}
        COMMAND='"$TMPDIR/CrashCore run -D $BINDIR -C $TMPDIR/jsons"'
        touch ${CRASHDIR}/configs/command.env
        setconfig TMPDIR ${TMPDIR} ${CRASHDIR}/configs/command.env
        setconfig BINDIR ${BINDIR} ${CRASHDIR}/configs/command.env
        setconfig COMMAND "$COMMAND" ${CRASHDIR}/configs/command.env && source ${CRASHDIR}/configs/command.env
        echo -e "Sing-Box-Puer内核 \033[32m配置成功！\033[0m"
    fi
}

settask(){
    source ${CRASHDIR}/task/task.sh
    set_service running "106" "运行时每5分钟自动保存面板配置" "*/5 * * * *"
    set_service afstart "107" "服务启动后自动同步ntp时间"
    cronset "在每天的3点整更新订阅并重启服务" "0 3 * * * ${CRASHDIR}/task/task.sh 104 在每天的3点整更新订阅并重启服务"
    echo -e "任务【在每天的3点整更新订阅并重启服务】\033[32m添加成功！\033[0m"
}

setyacdip(){
    host=$(ip a | grep -w 'inet' | grep 'global' | grep 'brd' | awk '{print $2}' | awk -F '/' '{print $1}' | head -n 1)
    [ -z "$db_port" ] && db_port=9999
    sed -ri "s/([0-9]{1,3}\.){3}[0-9]{1,3}/${host}/g" ${CRASHDIR}/ui/*.html
    sed -ri "s/([0-9]{1,3}\.){3}[0-9]{1,3}:9090/${host}:${db_port}/g" ${CRASHDIR}/ui/*.html
    echo -e "面板IP\033[32m变更成功！\033[0m"
}

BASEDIR=$(dirname $0)

if [ -z "$CRASHDIR" ]; then
    if [ -d /etc/ShellCrash ];then
        cp -r /etc/ShellCrash /tmp/SC_tmp && source /tmp/SC_tmp/init.sh
        [ -z "$(grep 'userguide=1' ${CRASHDIR}/configs/ShellCrash.cfg)" ] && echo -e "1\n0\n0\n0\n0\n" | crash
        echo -e "ShellCrash \033[32m初始化成功！\033[0m"
    elif [ -f $BASEDIR/ShellCrash.tar.gz ]; then
        mkdir -p /tmp/SC_tmp/ && tar -zxf $BASEDIR/ShellCrash.tar.gz -C /tmp/SC_tmp/ && source /tmp/SC_tmp/init.sh
        [ -z "$(grep 'userguide=1' ${CRASHDIR}/configs/ShellCrash.cfg)" ] && echo -e "1\n0\n0\n0\n0\n" | crash
        echo -e "ShellCrash \033[32m安装成功！\033[0m"
    fi
fi

[ -z "$CRASHDIR" ] && echo "系统安装失败。" && exit 1

if [ ! -f $CRASHDIR/CrashCore.tar.gz -a -f $BASEDIR/singboxp-linux-amd64.tar.gz ]; then
    cp -f $BASEDIR/singboxp-linux-amd64.tar.gz $CRASHDIR/CrashCore.tar.gz
    echo -e "Sing-Box-Puer内核 \033[32m安装成功！\033[0m"
fi

if [ -z "$(grep 'crashcore=singbox' ${CRASHDIR}/configs/ShellCrash.cfg)" ]; then
    setconfig redir_mod Tproxy模式
    setconfig update_url \'\'
    setconfig url_id 103
    setconfig release_type master
    setsingboxp
    settask
fi

if [ ! -d $CRASHDIR/ui -a -f $BASEDIR/meta_yacd.tar.gz ]; then
    rm -rf $CRASHDIR/ui && mkdir -p $CRASHDIR/ui
    tar -zxf $BASEDIR/meta_yacd.tar.gz -C $CRASHDIR/ui
    echo -e "yacd ui 面板 \033[32m安装成功！\033[0m"
fi
echo -e "订阅转换使用方法: /usr/share/sub/sub -url http://www.订阅1.com http://订阅2.com ..."

[ -f ${CRASHDIR}/ui/index.html ] && [ -n "$(grep yacd ${CRASHDIR}/ui/index.html)" ] && setyacdip

if [ ! -f $CRASHDIR/jsons/dns.json ]; then
    cat > $CRASHDIR/jsons/dns.json <<EOF
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
EOF
    setconfig dns_mod mix
    setconfig dns_nameserver \'null\'
    setconfig dns_fallback \'null\'
fi

[ ! -f $CRASHDIR/configs/web_save ] && cat > "$CRASHDIR"/configs/web_save <<EOF
🔰 组选择,🇨🇳台湾组
🧩 ChatGPT,🇺🇸美国组
YouTube,🔰 组选择
Google,🔰 组选择
🍺 Github,🔰 组选择
🐟 漏网之鱼,🔰 组选择
EOF