#-*- coding: utf-8 -*-
"""OpenFlow控制器主程序，OFAgentRyuApp继承app_manager.RyuApp
   实现OpenFlow交换机与控制器的通信，如端口管理，PacketIn/
   PacketOut消息等管理.
"""

import logging
import os
import struct
from webob import Response

from eventlet import greenthread
from requests.exceptions import ConnectionError

from ryu import cfg
from ryu.app.wsgi import route
from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import handler
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_2 as ryu_ofp12

from daolicontroller.client import DockerHTTPClient
from daolicontroller.ipam import IPAM
from daolicontroller.lib import PacketARP, PacketIPv4
from daolicontroller.objects import PortState
from daolicontroller.objects import Container

try:
    import json
except ImportError:
    import simplejson as json

CONF = cfg.CONF

CONF.register_opts([
    cfg.StrOpt('api_url', default='http://127.0.0.1:3380',
               help='daolinet api url'), # DaoliNet API服务的URL默认值
])

LOG = logging.getLogger(__name__)

# OpenFlow对外提供的API接口，主要功能为:当使用disconnect命令时实时删除已经建立的流表.
class GroupController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(GroupController, self).__init__(req, link, data, **config)
        self.app = data['app']

    @route('policy', '/v1/policy', methods=['POST'])
    def delete(self, _req, **kwargs):
        # 从POST请求体中解析容器的id信息
        body = json.loads(_req.body)

        # 如果请求中不包涵两个容器的id直接返回错误状态
        if not body.has_key('sid') or not body.has_key('did'):
            return Response(status=400)

        # 调用flow_delete删除对应的流表
        self.app.flow_delete(body['sid'], body['did'])
        return Response(status=200)

# 继承app_manager.RyuApp实现OpenFlow交换机与控制器的通信，并处理各种OpenFlow消息
class OFAgentRyuApp(app_manager.RyuApp):
    OFP_VERSIONS = [ryu_ofp12.OFP_VERSION]
    # 启动程序时，加载Ryu的DPSet和WSGI模块
    # DPSet: 管理OpenFlow交换机以及端口信息
    # WSGIApplication: 对外提供API接口
    _CONTEXTS = {'dpset': dpset.DPSet,
                 'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(OFAgentRyuApp, self).__init__(*args, **kwargs)
        self.port_state = {}
        self.dps = kwargs['dpset'].dps
        # 初始化PacketLib类，准备接收PacketIn消息
        self.packetlib = PacketLib(self)
        kwargs['wsgi'].register(GroupController, {'app': self.packetlib})

    # 声明OpenFlow交换机消息，处理连接和断开操作
    @handler.set_ev_cls(dpset.EventDP)
    def dp_hadler(self, ev):
        dpid = ev.dp.id
        if ev.enter:
            # 当OpenFlow交换机连接控制器时，将交换机端口信息储存到PortState中
            if dpid not in self.port_state:
                self.port_state[dpid] = PortState()
                for port in ev.ports:
                    self.port_state[dpid].add(port)
            # 初始化一些流表，比如控制器自身端口，数据库端口和API服务端口等
            self.packetlib.init_flow(ev.dp)
        else:
            # 当OpenFlow交换机与控制器断开时，将端口信息从PortState中删除
            if dpid in self.port_state:
                for port in self.port_state[dpid].values():
                    self.port_state[dpid].remove(port)
                del self.port_state[dpid]

    # 当容器网卡添加到OpenFlow交换机时执行添加操作
    @handler.set_ev_cls(dpset.EventPortAdd)
    def port_add_handler(self, ev):
        self.port_state[ev.dp.id].add(ev.port)

    # 当容器网卡从OpenFlow交换机删除时执行删除操作
    @handler.set_ev_cls(dpset.EventPortDelete)
    def port_del_handler(self, ev):
        self.port_state[ev.dp.id].remove(ev.port)

    # 当容器网卡有改动时执行修改操作
    @handler.set_ev_cls(dpset.EventPortModify)
    def port_mod_handler(self, ev):
        self.port_state[ev.dp.id].add(ev.port)

    # 当OpenFlow发送PacketIn消息时执行处理流程
    @set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        try:
            # 进入PacketLib类的packet_in_handler函数
            self.packetlib.packet_in_handler(ev)
        except ConnectionError:
            LOG.warn("Connection aborted. Retring again.")
            greenthread.sleep(2)

# 处理流表初始化以及PacketIn消息流程
class PacketLib(object):

    def __init__(self, ryuapp):
        super(PacketLib, self).__init__()
        self.gateway = {}
        # 初始化物理IP地址管理类
        self.ipam = IPAM()
        # 保存容器网络信息
        self.container = Container()
        # 调用DaoliNet API Service的客户端类
        self.client = DockerHTTPClient(self, CONF.api_url)
        # 获取所有主机(网关)信息
        self.client.gateways()
        # 获取所有容器信息
        self.client.containers()
        # 初始化ARP协议处理类
        self.arp = PacketARP(self, ryuapp)
        # 初始化IP协议处理类
        self.ipv4 = PacketIPv4(self, ryuapp)

    def gateway_get(self, dpid):
        """获取gateway信息，如果不存在，则调用api获取；如果已经存在则返回"""
        normal_dpid = dpid_lib.dpid_to_str(dpid)
        gateway = self.gateway.get(normal_dpid)
        if not gateway:
            gateway = self.client.gateway(normal_dpid)
        return gateway

    def packet_in_handler(self, ev):
        """处理PacketIn消息，从数据包中解析协议信息并执行不同的动作.

           1.通过datapath.id获取网关信息
           2.解析数据包中mac,arp/ip以及tcp/udp信息
           3.执行不同流程生成流表
             ARP: 构造ARP Response返回给交换机
             IP: 生成mod mac和mod ip流表
        """
        msg = ev.msg
        datapath = msg.datapath
        port = msg.match['in_port']

        # 根据datapath id获取网关信息，不存在则退出
        gateway = self.gateway_get(datapath.id)
        if gateway is None:
            return

        # 解析数据包，获取二，三，四层信息
        pkt = packet.Packet(msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)

        if not pkt_ethernet:
            LOG.info("drop non-ethernet packet")
            return

        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)

        # 如果为ARP数据包并且为ARP Request数据包，则执行arp流程
        # 如果为IPv4数据包则执行IP处理流程
        if pkt_arp:
            if pkt_arp.opcode == arp.ARP_REQUEST:
                self.arp.run(msg, pkt_ethernet, pkt_arp, gateway)
        elif pkt_ipv4:
            pkt_tp = pkt.get_protocol(tcp.tcp) or \
                     pkt.get_protocol(udp.udp) or \
                     pkt.get_protocol(icmp.icmp)

            LOG.debug("packet-in msg %s %s %s from %s", 
                      datapath.id, pkt_ipv4, pkt_tp, port)

            if pkt_tp and port:
                self.ipv4.run(msg, pkt_ethernet, pkt_ipv4, pkt_tp, gateway)
        else:
            LOG.debug("drop non-arp and non-ip packet")

    # 初始化arp和ip流表
    def init_flow(self, dp):
        gateway = self.gateway_get(dp.id)
        if gateway is not None:
            self.arp.init_flow(dp, gateway)
            self.ipv4.init_flow(dp, gateway)

    # 删除建立的流表
    def flow_delete(self, sid, did):
        self.ipv4.flow_delete(sid, did)
