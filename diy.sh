# 此脚本用处是：定制个性化参数
#============================================================================================


# 1-设置默认主题
sed -i 's/bootstrap/opentomcat/g' ./feeds/luci/collections/luci/Makefile

# 2-设置管理地址
sed -i 's/192.168.1.1/192.168.5.100/g' package/base-files/files/bin/config_generate

# 4-设置密码为空
sed -i '/CYXluq4wUazHjmCDBCqXF/d' package/lean/default-settings/files/zzz-default-settings

# 5-修改时间格式
sed -i 's/os.date()/os.date("%Y-%m-%d %H:%M:%S")/g' package/lean/autocore/files/*/index.htm

# 6-添加固件日期
sed -i 's/IMG_PREFIX:=/IMG_PREFIX:=$(BUILD_DATE_PREFIX)-/g' ./include/image.mk
sed -i '/DTS_DIR:=$(LINUX_DIR)/a\BUILD_DATE_PREFIX := $(shell date +'%F')' ./include/image.mk

# 7-修正硬件信息
sed -i 's/${g}.*/${a}${b}${c}${d}${e}${f}${hydrid}/g' package/lean/autocore/files/x86/autocore

# 8-增固件连接数
sed -i '/customized in this file/a net.netfilter.nf_conntrack_max=165535' package/base-files/files/etc/sysctl.conf

mkdir -p files/etc/ShellCrash/ui
curl -fsSL https://raw.githubusercontent.com/juewuy/ShellCrash/master/bin/ShellCrash.tar.gz | tar -zxC files/etc/ShellCrash
curl -fsSL https://raw.githubusercontent.com/juewuy/ShellCrash/master/bin/dashboard/meta_yacd.tar.gz | tar -zxC files/etc/ShellCrash/ui
curl -fsSL https://raw.githubusercontent.com/cgistar/openwrt-tiny/main/sub/bin/sub-openwrt-x86_64.tar.gz | tar -zxC files/usr/share/sub
curl -o files/etc/ShellCrash/CrashCore.tar.gz -fsSL https://raw.githubusercontent.com/juewuy/ShellCrash/master/bin/singboxp/singbox-linux-amd64.tar.gz
chmod +x files/usr/share/sub/install_sc.sh
chmod +x files/usr/share/sub/sub
