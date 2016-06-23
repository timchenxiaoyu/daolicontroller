#-*- coding: utf-8 -*-
"""DaoliNet OpenFlow控制器入口程序，由服务程序调用main方法."""

from ryu.lib import hub
hub.patch(thread=False)

import logging
import sys

from oslo_config import cfg

from ryu import cfg as ryu_cfg
from ryu import log
log.early_init_log(logging.DEBUG)

from ryu.base.app_manager import AppManager

CONF = cfg.CONF
CONF.register_cli_opts([
    cfg.BoolOpt('enable-debugger', default=False,
                help='don\'t overwrite Python standard threading library'
                '(use only for debugging)'),
])

def main(args=None, prog=None):
    try:
        # 预加载配置选项和文件，包括所有由CONF变量指定的选项
        CONF(args=args, prog=prog,
             project='daolicontroller', version='1.1',
             default_config_files=['/etc/daolicontroller/daolicontroller.conf'])
    except cfg.ConfigFilesNotFoundError:
        CONF(args=args, prog=prog,
             project='daolicontroller', version='1.1')

    # 初始化日志，完成日志格式的定义等
    log.init_log()

    # 将Ryu中定义的变量合并到当前CONF中.
    if ryu_cfg.CONF is not CONF:
        ryu_cfg.CONF(args=args, project='ryu')

    if CONF.enable_debugger:
        LOG = logging.getLogger('daolicontroller')
        msg = 'debugging is available (--enable-debugger option is turned on)'
        LOG.info(msg)
    else:
        hub.patch(thread=True)

    # 通过Ryu加载主控制器ofa_agent中定义的应用程序
    AppManager.run_apps(['daolicontroller.ofa_agent'])
