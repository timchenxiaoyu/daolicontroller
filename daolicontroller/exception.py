"""定义的一些异常类.

   OPFException: 异常基类
   DevicePortNotFound: OpenFlow交换机不存在某个网卡设备
   NotFound: 不存在某个资源
   ContainerNotFound: 不存在指定容器
"""


class OPFException(Exception):
    message = "An unknown exception occurred."

    def __init__(self, msg=None, **kwargs):
        self.kwargs = kwargs

        if not msg:
            msg = self.message

            try:
                msg = msg % kwargs
            except Exception:
                # at least get the core message out if something happened
                msg = self.message

        super(OPFException, self).__init__(msg)

    def format_message(self):
        return self.args[0]

class DevicePortNotFound(OPFException):
    message = 'no such network device %(device)s'

class NotFound(OPFException):
    message = "Resource could not be found."

class ContainerNotFound(NotFound):
    message = "Container %(container)s could not be found."
