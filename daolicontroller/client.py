#-*- coding: utf-8 -*-
"""调用Docker HTTPClient获取容器以及网络信息."""

import logging
import os
import collections

from docker import client
from docker import tls
from ryu import cfg

docker_opts = [
    cfg.BoolOpt('api_insecure',
                default=False,
                help='If set, ignore any SSL validation issues'),
    cfg.StrOpt('ca_file',
               help='Location of CA certificates file for '
                    'securing docker api requests (tlscacert).'),
    cfg.StrOpt('cert_file',
               help='Location of TLS certificate file for '
                    'securing docker api requests (tlscert).'),
    cfg.StrOpt('key_file',
               help='Location of TLS private key file for '
                    'securing docker api requests (tlskey).'),
]

CONF = cfg.CONF
CONF.register_opts(docker_opts, 'docker')

DOCKER_PLUGIN = 'daolinet'
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_DOCKER_API_VERSION = '1.19'

LOG = logging.getLogger(__name__)


class DockerHTTPClient(client.Client):
    def __init__(self, parent, url):
        """初始化变量，用来存放证书信息生成http请求."""
        self._parent = parent
        if (CONF.docker.cert_file or
                CONF.docker.key_file):
            client_cert = (CONF.docker.cert_file, CONF.docker.key_file)
        else:
            client_cert = None
        if (CONF.docker.ca_file or
                CONF.docker.api_insecure or
                client_cert):
            ssl_config = tls.TLSConfig(
                client_cert=client_cert,
                ca_cert=CONF.docker.ca_cert,
                verify=CONF.docker.api_insecure)
        else:
            ssl_config = False
        super(DockerHTTPClient, self).__init__(
            base_url=url,
            version=DEFAULT_DOCKER_API_VERSION,
            timeout=DEFAULT_TIMEOUT_SECONDS,
            tls=ssl_config
        )

    def containers(self):
        """调用Swarm Network API获取所有网络和容器网络信息.
           同时只过滤出Driver为'daolinet'的网络.
        """
        res = self._result(self._get(self._url("/networks")), True)
        for r in res:
            if r['Driver'] != DOCKER_PLUGIN:
                continue
            for k, v in r['Containers'].iteritems():
                # Docker Swarm在返回时会返回以ep-打头的重复容器，所以需要去除
                if not k.startswith('ep-'):
                    v['Id'], v['NetworkId'], v['NetworkName'] = k, r['Id'], r['Name']
                    # 将容器添加到全container全局变量中以备后续使用
                    self._parent.container.new(v)
                    self.node(k)
        return res

    def node(self, container):
        """从Swarm API中获取到的容器信息中不包涵物理IP地址和网关信息,
           需要调用额外函数或API获取."""
        obj = self._parent.container[container]
        # 如果没有物理IP地址，则调用alloc分配一个物理IP地址
        if not obj.has_key('UIPAddress'):
            try:
                obj['UIPAddress'] = self._parent.ipam.alloc()
            except Exception as e:
                LOG.warn(e.message)

        # 如果没有Node的信息，调用Swarm API获取Node信息
        if not obj.has_key('Node'):
            try:
                info = self.inspect_container(container)
                obj['Node'] = info['Node']['IP']
            except Exception as e:
                LOG.warn(e.message)
                return None

        # 如果没有网关DataPath信息，则通过Node信息从gateway列表中获取.
        if not obj.has_key('DataPath'):
            for dpid, item in self._parent.gateway.iteritems():
                if item['Node'] == obj['Node']:
                    obj['DataPath'] = dpid
                    break

        return obj['Node']

    def gateways(self):
        """调用DaoliNet API获取所有保存的网关信息."""
        res = self._result(self._get(self._url("/api/gateways")), True)
        for r in res:
            self._parent.gateway[r['DatapathID']] = r
        return res

    def gateway(self, dpid):
        """调用DaoliNet API获取指定id的网关信息."""
        url = self._url("/api/gateways/%s" % dpid)
        try:
            res = self._result(self._get(url), True)
            self._parent.gateway[res['DatapathID']] = res
        except:
            res = None
        return res

    def policy(self, peer):
        """调用DaoliNet API获取两个容器的状态: connect或disconnect."""
        url = self._url("/api/policy/%s" % peer)
        return self._result(self._get(url))

    def group(self, src, dst):
        """调用DaoliNet API获取groups信息，判断两个网络是否在同一个group中.

           如果在同一group中返回True，否则返回False.
        """
        member_dict = {}
        res = self._result(self._get(self._url("/api/groups")), True)
        for r in res:
            url = self._url("/api/groups/" + r)
            members = self._result(self._get(url), True)
            for m in members:
                if m == src:
                    member_dict[r] = members
                    break

        for group, members in member_dict.items():
            for m in members:
                if m == dst:
                    return True
        return False

    def firewall(self, node, port):
        """调用DaoliNet API获取指定port对应的防火墙信息.

        如果存在返回Firewall信息，否则返回None.
        """
        url = self._url("/api/firewalls/{0}/{1}".format(node, port))
        try:
            return self._result(self._get(url), True)
        except:
            return None
