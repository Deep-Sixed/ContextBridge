"""Network jail for the failover acceptance test (tests/test_failover.py).

Python imports ``sitecustomize`` at startup from ``PYTHONPATH``, so every process
the test starts -- gateways, agent, admin CLI, drill -- loads this first. Desktop
Commander's remote mode depends on a hosted relay; ContextBridge must depend on
nothing off this machine. Here every destination except loopback and this host's
own name is refused, and each attempt is appended to ``$CONTEXTBRIDGE_JAIL_LOG``
for the test to fail on.

Name resolution is jailed on every OS. Direct connects to IP literals are jailed
wherever they go through ``socket.connect`` (all blocking sockets, and asyncio
outside Windows' proactor loop).
"""

import ipaddress
import os
import socket

_LOG = os.environ.get("CONTEXTBRIDGE_JAIL_LOG")
_OWN_NAMES = {"", "localhost", "localhost.localdomain", socket.gethostname().lower()}


def _record(kind, target):
    if _LOG:
        with open(_LOG, "a", encoding="utf-8") as fh:
            fh.write(f"{os.getpid()} {kind} {target!r}\n")


def _local(host):
    if host is None:
        return True  # a wildcard, as used for binding
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    host = str(host).strip("[]").split("%")[0].lower()
    if host in _OWN_NAMES:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_unspecified


_getaddrinfo = socket.getaddrinfo


def getaddrinfo(host, *args, **kwargs):
    if not _local(host):
        _record("resolve", host)
        raise socket.gaierror(socket.EAI_NONAME, f"failover jail: {host} is off this machine")
    return _getaddrinfo(host, *args, **kwargs)


def _jailed(method):
    def guarded(self, address, *args):
        if self.family in (socket.AF_INET, socket.AF_INET6) and isinstance(address, tuple) and not _local(address[0]):
            _record("connect", address[:2])
            raise ConnectionRefusedError(f"failover jail: {address[0]} is off this machine")
        return method(self, address, *args)

    return guarded


socket.getaddrinfo = getaddrinfo
socket.socket.connect = _jailed(socket.socket.connect)
socket.socket.connect_ex = _jailed(socket.socket.connect_ex)
