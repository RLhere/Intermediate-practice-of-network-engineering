### 
# @Description: 
 # @Version: 
 # @Author: Kevin Liu
 # @Date: 2019-11-25 14:34:27
 # @LastEditors: Kevin Liu
 # @LastEditTime: 2019-11-25 14:42:55
 ###
ifconfig
iwconfig
ifconfig wlan0 down
iwconfig wlan0 mode Monitor
ifconfig wlan0 up
iwconfig wlan0

tcpdump -i wlan0

# antenna
# libpcap函数库  可以过滤载荷
# example： tcpdump tcp dst port 80 wlan0
# example:  tcpdump ip
# example:  tcpdump udp post 53 dns
# example:  tcp dst port 110
# 两个函数： packet filter

# Get: Http/1.1 /r/n host: www.baidu.com /r/n user-agent: HuaWei P10 /r/n  whois host