#-*- coding: utf-8 -*-
"""
容器物理IP地址管理. IP地址的管理和释放.
"""

from ryu import cfg

from netaddr import IPAddress
from netaddr import IPNetwork

CONF = cfg.CONF
# 默认物理IP地址段为10.0.0/8,可以通过修改配置来改变
CONF.register_opt(cfg.StrOpt('iprange', default='10.0.0.0/8',
                             help='The ip range'))

class IPAM(object):
    def __init__(self, iprange=None):
        """初始化变量，first保存.1地址，last保存.254地址."""
        if iprange is None:
            iprange = CONF.iprange

        net = IPNetwork(iprange)
        self.first = IPAddress(net.first + 1)
        self.last = IPAddress(net.last - 1)
        self.unused = set()

    def alloc(self):
        """IP地址分配，首先从unused中获取，如果没有则从first变量获取并加1,
           如果first等于last表示没有可用IP地址分配.
        """
        if len(self.unused) > 0:
            return self.unused.pop()

        if self.first == self.last:
            raise Exception("All ips allocated.")

        ip = self.first
        self.first += 1
        
        return str(ip)

    def deloc(self, ip):
        """当容器删除时，释放物理IP地址(保存到unused变量中)"""
        self.unused.add(ip)
