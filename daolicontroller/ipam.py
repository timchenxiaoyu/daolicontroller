"""
Underlay physical address for container.
"""

from ryu import cfg

from netaddr import IPAddress
from netaddr import IPNetwork

CONF = cfg.CONF
CONF.register_opt(cfg.StrOpt('iprange', default='10.0.0.0/8',
                             help='The ip range'))

class IPAM(object):
    def __init__(self, iprange=None):
        if iprange is None:
            iprange = CONF.iprange

        net = IPNetwork(iprange)
        self.first = net.first + 1
        self.last = net.last - 1

        self.unused = []

    def alloc(self):
        if len(self.unused) > 0:
            ip = self.unused.pop()
        else:
            if self.first == self.last:
                raise Exception("All ips allocated.")

            ip = self.first
            self.first += 1
        
        return str(IPAddress(ip))

    def deloc(self, ip):
        self.unused.append(IPAddress(ip).value)
