#!/bin/ash

[ -f $CRASHDIR/CrashCore.tar.gz ] && echo "系统核心已安装。" && exit 1

BASEDIR=$(dirname $0)

if [ -f $BASEDIR/ShellCrash.tar.gz ]; then
    mkdir -p /tmp/SC_tmp/ && tar -zxf $BASEDIR/ShellCrash.tar.gz -C /tmp/SC_tmp/ && source /tmp/SC_tmp/init.sh
    echo -e "1\n1\n0\n0\n0\n" | crash
    echo -e "9\n7\nb\n3\n0\n0\n" | crash
fi

[ ! $CRASHDIR ] && echo "系统未安装。" && exit 1

if [ -f $BASEDIR/meta_yacd.tar.gz ]; then
    rm -rf $CRASHDIR/ui && mkdir -p $CRASHDIR/ui
    tar -zxf $BASEDIR/meta_yacd.tar.gz -C $CRASHDIR/ui
    host=$(ip a | grep -w 'inet' | grep 'global' | grep 'brd' | awk '{print $2}' | awk -F '/' '{print $1}')
    sed -i "s/127.0.0.1:9090/${host}:9999/g" ${CRASHDIR}/ui/*.html
fi

if [ -f $BASEDIR/singboxp-linux-amd64.tar.gz ]; then
    tar -zxf $BASEDIR/singboxp-linux-amd64.tar.gz -C /tmp/
    echo -e "1\n5\n0\n0\n" | crash
fi

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
    echo -e "2\n1\n3\n0\n2\n4\n1\nnull\n2\nnull\n0\n3\n0\n0\n" | crash
fi
echo -e "5\n1\n4\n2\n3\n0\n1\n0\n0\n" | crash
