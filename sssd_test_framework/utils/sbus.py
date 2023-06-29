# Created on : Jun 29, 2023, 3:49:30 PM
# Author     : allopez

from __future__ import annotations

import pytest
#from sssd_test_framework.roles.client import Client


class SBUSObject:
    dbus_script = """
import re
from pydbus import SystemBus, connect


class DBusProxy:
    _node_regex = '<node\\s+name\\s*=\\s*"([._a-zA-Z][._a-zA-Z0-9]*)"\\s*/?>'

    def __init__(self, name, bus_path=None, root_obj_path='/'):
        self._name = name
        self._bus = SystemBus() if bus_path is None else connect(bus_path)
        self._root_path = root_obj_path if root_obj_path == '/' else root_obj_path + '/'
        self._root = self._bus.get(self._name, root_obj_path)
        self._nodes = []
        for node in re.finditer(self._node_regex, self._root.Introspect()):
            self._nodes.append(node.group(1))

    def __getattr__(self, attr):
        if attr in self._nodes:
            value = self._bus.get(self._name, self._root_path + attr)
            self.__setattr__(attr, value)
            return value

        # If the attribute doesn't exist, replace the exception.
        # Let flow any other exception.
        try:
            return self._root.__getattribute__(attr)
        except AttributeError:
            raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{attr}'")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        for n in self._nodes:
            if n in self.__dict__:
                self.__delattr__(n)


def getFinalWord(str, sep='/'):
    pos = (len(str) - str.rfind(sep) - 1) * -1
    return str[pos:]


class SBusProxy(DBusProxy):
    SYSTEM_BUS = None
    PRIVATE_BUS_PREFIX = 'unix:path=/var/lib/sss/pipes/private/'
    MONITOR_BUS = PRIVATE_BUS_PREFIX + 'sbus-monitor'
    INFOPIPE_SERVICE = 'org.freedesktop.sssd.infopipe'
    INFOPIPE_ROOT = '/org/freedesktop/sssd/infopipe'


class SBusInfoPipeProxy(SBusProxy):
    def __init__(self):
        super().__init__(name=self.INFOPIPE_SERVICE,
                         bus_path=self.SYSTEM_BUS,
                         root_obj_path=self.INFOPIPE_ROOT)

    def __getattr__(self, attr):
        if attr == 'Domains':
            self.Domains = {}
            for d in self._root.ListDomains():
                domain = getFinalWord(d)
                self.Domains[domain] = self._bus.get(self._bus_name, 'Domains/' + domain)
            return self.Domains

        return super().__getattr__(attr)

"""

    def __init__(self, ssh, base_class):
        self._ssh = ssh
        self._base_class = base_class

    def run(self, command):
        main = f'print({self._base_class}.{command})'

        result = self._ssh.run('/usr/bin/python -', input=self.dbus_script + main)
        if result.rc != 0:
            raise RuntimeError("Operation failed")
        return result.stdout

    def __enter__(self):
        return self

    def __exit__(*args):
        pass


class SBUSInfoPipe(SBUSObject):
    def __init__(self, ssh):
        super().__init__(ssh, 'SBusInfoPipeProxy()')


class SBUSUtils:
    def __init__(self, ssh):
        self.ifp = SBUSInfoPipe(ssh)

    def __enter__(self):
        return self

    def __exit__(*args):
        pass
