# 此脚本用处是：添加第三方插件
# https://github.com/P3TERX/Actions-OpenWrt
#=========================================================================================================================


# 编译内核版本
sed -i 's/KERNEL_PATCHVER:=6.1/KERNEL_PATCHVER:=6.6/g' ./target/linux/x86/Makefile

# 1-添加 lucky 插件
git clone https://github.com/gdy666/luci-app-lucky.git package/lucky

# 2-添加 PowerOff 关机插件
git clone https://github.com/WukongMaster/luci-app-poweroff.git package/luci-app-poweroff

# 3-添加 opentomcat 主题
git clone https://github.com/WukongMaster/luci-theme-opentomcat.git package/luci-theme-opentomcat
rm -rf feeds/luci/themes/luci-theme-design
rm -rf feeds/luci/applications/luci-app-design-config
git clone https://github.com/gngpp/luci-theme-design.git feeds/luci/themes/luci-theme-design
git clone https://github.com/gngpp/luci-app-design-config.git feeds/luci/applications/luci-app-design-config
