#-*- coding: utf-8 -*-
"""定义一些全局变量类.

   Container: 保存容器网络信息.
   PortState: 交换机端口信息.
"""

from netaddr import IPNetwork

class Container(dict):
    def new(self, container):
        """将容器的IPv4Address，Id, EndpointID, MacAddress信息保存起来."""
        key = str(IPNetwork(container['IPv4Address']).ip)
        container['IPv4Address'] = key
        self[key] = container
        self[container['Id']] = container
        self[container['EndpointID']] = container
        self[container['MacAddress']] = container

class PortState(dict):
    def __init__(self):
        super(PortState, self).__init__()

    def add(self, port):
        """以容器网卡端口号和容器网卡名为key，存储port信息."""
        self[port.port_no] = self[port.name] = port

    def remove(self, port):
        """删除容器网卡端口号和网卡名为key的数据."""
        if self.has_key(port.port_no):
            del self[port.port_no]
        if self.has_key(port.name):
            del self[port.name]
