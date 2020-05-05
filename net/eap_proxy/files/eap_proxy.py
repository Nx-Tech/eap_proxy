#!/usr/bin/env python

# Python EAP proxy for rediecting EAP packets
# Based on: https://github.com/jaysoffian/eap_proxy

"""
Usage: eap_proxy [--daemon] [--pidfile PIDFILE]
                 [--syslog] [--run-as USER[:GROUP]]
                 [--promiscuous] [--debug] [--debug-packets]
                 [-h, --help]
                 IF_WAN IF_ROUTER

Interface arguments:
  IF_WAN                ONT Interface
  IF_ROUTER             Gateway/Router Interface

Process management:
  --daemon              Run in background until killed; implies --syslog
  --pidfile PIDFILE     Record PID to PIDFILE
  --syslog              Log to syslog instead of stderr
  --run-as USER[:GROUP] Switch to USER[:GROUP] after opening sockets;
                        incompatible with --daemon

Debugging:
  --promiscuous         Place interface into promiscuous mode instead of
                        multicast
  --debug               Enable debug logging
  --debug-packets       Print packets in hex format to assist with debugging;
                        implies --debug

Help:
  -h, --help            Show this help message
"""

import argparse
import atexit
import ctypes
import ctypes.util
import logging
import logging.handlers
import os
import pwd, grp
import re
import select
import signal
import socket
import struct
import sys
import time
import traceback
from collections import namedtuple

# Constants

EAP_MULTICAST_ADDR = (0x01, 0x80, 0xC2, 0x00, 0x00, 0x03)
ETH_P_PAE = 0x888E  # IEEE 802.1X (Port Access Entity)
IFF_PROMISC = 0x100
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_MULTICAST = 0
PACKET_MR_PROMISC = 1
SIOCGIFADDR = 0x8915
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
SOL_PACKET = 263

# Python 2 / 3 compatibility

PY3 = sys.version_info[0] == 3

try:
    xrange
except NameError:
    xrange = range


def to_utf8(s):
    return s if isinstance(s, bytes) else s.encode("utf8")


try:
    if_nametoindex = socket.if_nametoindex  # Python 3.3
except AttributeError:
    _if_nametoindex = ctypes.CDLL(ctypes.util.find_library("c")).if_nametoindex

    def if_nametoindex(ifname):
        return _if_nametoindex(to_utf8(ifname))


# Sockets / Network Interfaces


class struct_packet_mreq(ctypes.Structure):
    _fields_ = (
        ("mr_ifindex", ctypes.c_int),
        ("mr_type", ctypes.c_ushort),
        ("mr_alen", ctypes.c_ushort),
        ("mr_address", ctypes.c_ubyte * 8),
    )


def addsockaddr(sock, address):
    """Configure physical-layer multicasting or promiscuous mode for `sock`.
       If `addr` is None, promiscuous mode is configured. Otherwise `addr`
       should be a tuple of up to 8 bytes to configure that multicast address.
    """
    mreq = struct_packet_mreq()
    mreq.mr_ifindex = if_nametoindex(getifname(sock))
    if address is None:
        mreq.mr_type = PACKET_MR_PROMISC
    else:
        mreq.mr_type = PACKET_MR_MULTICAST
        mreq.mr_alen = len(address)
        mreq.mr_address = address
    sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)


def rawsocket(ifname, promisc=False):
    """Return raw socket listening for 802.1X packets on `ifname` interface.
       The socket is configured for multicast mode on EAP_MULTICAST_ADDR.
       Specify `promisc` to enable promiscuous mode instead.
    """
    s = socket.socket(
        socket.PF_PACKET,
        socket.SOCK_RAW,
        socket.htons(ETH_P_PAE),
    )
    s.bind((ifname, 0))
    addsockaddr(s, None if promisc else EAP_MULTICAST_ADDR)
    return s


def getifname(sock):
    """Return interface name of `sock`"""
    return sock.getsockname()[0]


# Helpers


def strbuf(buf):
    """Return `buf` formatted as a hex dump (like tcpdump -xx)."""
    out = []
    tobyte = (lambda x: x) if (PY3 and isinstance(buf, bytes)) else ord
    for i in xrange(0, len(buf), 16):
        octets = (tobyte(x) for x in buf[i : i + 16])
        pairs = []
        for octet in octets:
            pad = "" if len(pairs) % 2 else " "
            pairs.append("%s%02x" % (pad, octet))
        out.append("0x%04x: %s" % (i, "".join(pairs)))
    return "\n".join(out)


def strmac(mac):
    """Return packed string `mac` formatted like aa:bb:cc:dd:ee:ff."""
    tobyte = (lambda x: x) if (PY3 and isinstance(mac, bytes)) else ord
    return ":".join("%02x" % tobyte(b) for b in mac[:6])


def strexc():
    """Return current exception formatted as a single line suitable
       for logging.
    """
    try:
        exc_type, exc_value, tb = sys.exc_info()
        if exc_type is None:
            return ""
        # Find last frame in this script
        lineno, func = 0, ""
        for frame in traceback.extract_tb(tb):
            if frame[0] != __file__:
                break
            lineno, func = frame[1:3]
        return "Exception in %s line %s (%s: %s)" % (
            func,
            lineno,
            exc_type.__name__,
            exc_value,
        )
    finally:
        del tb


def killpidfile(pidfile, signum):
    """Send `signum` to PID recorded in `pidfile`.
       Return PID if successful, else return None.
    """
    try:
        with open(pidfile) as f:
            pid = int(f.readline())
        os.kill(pid, signum)
        return pid
    except (EnvironmentError, ValueError):
        pass


def checkpidfile(pidfile):
    """Check whether a process is running with the PID in `pidfile`.
       Return PID if successful, else return None.
    """
    return killpidfile(pidfile, 0)


def writepidfile(pidfile):
    """Write current pid to `pidfile`."""
    with open(pidfile, "w") as f:
        f.write("%s\n" % os.getpid())

    # NOTE: Called on normal Python exit, but not on SIGTERM.
    @atexit.register
    def removepidfile(_remove=os.remove):
        try:
            _remove(pidfile)
        except Exception:
            pass


def daemon():
    """Convert process into a daemon."""
    if os.fork():
        sys.exit(0)
    os.chdir("/")
    os.setsid()
    os.umask(0)
    if os.fork():
        sys.exit(0)
    sys.stdout.flush()
    sys.stderr.flush()
    nullin = open("/dev/null", "r")
    nullout = open("/dev/null", "a+")
    nullerr = open("/dev/null", "a+")
    os.dup2(nullin.fileno(), sys.stdin.fileno())
    os.dup2(nullout.fileno(), sys.stdout.fileno())
    os.dup2(nullerr.fileno(), sys.stderr.fileno())


def run_as(username, groupname=""):
    """Switch process to run as `username` and optionally `groupname`."""
    pw = pwd.getpwnam(username)
    uid = pw.pw_uid
    gid = grp.getgrnam(groupname).gr_gid if groupname else pw.pw_gid
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


def make_logger(use_syslog=False, debug=False):
    """Return new logging.Logger object."""
    if use_syslog:
        formatter = logging.Formatter("eap_proxy[%(process)d]: %(message)s")
        formatter.formatException = lambda *__: ""  # No stack trace to syslog
        SysLogHandler = logging.handlers.SysLogHandler
        handler = SysLogHandler("/dev/log", facility=SysLogHandler.LOG_DAEMON)
        handler.setFormatter(formatter)
    else:
        formatter = logging.Formatter("[%(asctime)s]: %(message)s")
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)

    logger = logging.getLogger("eap_proxy")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.addHandler(handler)
    return logger


# EAP Decoding
# cf. https://github.com/the-tcpdump-group/tcpdump/blob/master/print-eap.c


class EAPFrame(namedtuple("EAPFrame", "dst src version type length packet")):
    __slots__ = ()
    _struct = struct.Struct("!6s6sHBBH")  # Includes ethernet header
    TYPE_PACKET = 0
    TYPE_START = 1
    TYPE_LOGOFF = 2
    TYPE_KEY = 3
    TYPE_ENCAP_ASF_ALERT = 4
    _types = {
        TYPE_PACKET: "EAP Packet",
        TYPE_START: "EAPOL Start",
        TYPE_LOGOFF: "EAPOL Logoff",
        TYPE_KEY: "EAPOL Key",
        TYPE_ENCAP_ASF_ALERT: "Encapsulated ASF Alert",
    }

    @classmethod
    def from_buf(cls, buf):
        unpack, size = cls._struct.unpack, cls._struct.size
        dst, src, etype, ver, ptype, length = unpack(buf[:size])
        if etype != ETH_P_PAE:
            raise ValueError("Invalid ethernet type: 0x%04x" % etype)
        if ptype == cls.TYPE_PACKET:
            packet = EAPPacket.from_buf(buf[size : size + length])
        else:
            packet = None
        return cls(dst, src, ver, ptype, length, packet)

    @property
    def type_name(self):
        return self._types.get(self.type, "???")

    @property
    def is_start(self):
        return self.type == self.TYPE_START

    @property
    def is_logoff(self):
        return self.type == self.TYPE_LOGOFF

    @property
    def is_success(self):
        return self.packet and self.packet.is_success

    def __str__(self):
        return "%s > %s, %s (%d) v%d, Length %d%s" % (
            strmac(self.src),
            strmac(self.dst),
            self.type_name,
            self.type,
            self.version,
            self.length,
            ", " + str(self.packet) if self.packet else "",
        )


class EAPPacket(namedtuple("EAPPacket", "code id length data")):
    __slots__ = ()
    _struct = struct.Struct("!BBH")
    REQUEST, RESPONSE, SUCCESS, FAILURE = 1, 2, 3, 4
    _codes = {
        REQUEST: "Request",
        RESPONSE: "Response",
        SUCCESS: "Success",
        FAILURE: "Failure",
    }

    @classmethod
    def from_buf(cls, buf):
        unpack, size = cls._struct.unpack, cls._struct.size
        code, id_, length = unpack(buf[:size])
        data = buf[size : size + length - 4]
        return cls(code, id_, length, data)

    @property
    def code_name(self):
        return self._codes.get(self.code, "???")

    @property
    def is_success(self):
        return self.code == self.SUCCESS

    def __str__(self):
        return "%s (%d) ID %d, Length %d [%d]" % (
            self.code_name,
            self.code,
            self.id,
            self.length,
            len(self.data),
        )


# EAP Proxy


class EAPProxy(object):
    _poll_events = {
        select.POLLERR: "POLLERR",
        select.POLLHUP: "POLLHUP",
        select.POLLNVAL: "POLLNVAL",
    }

    def __init__(self, args, log):
        self.args = args
        self.log = log
        self.s_rtr = rawsocket(args.if_rtr, promisc=args.promiscuous)
        self.s_wan = rawsocket(args.if_wan, promisc=args.promiscuous)

    def proxy_loop(self):
        poll = select.poll()
        poll.register(self.s_rtr, select.POLLIN)
        poll.register(self.s_wan, select.POLLIN)
        socks = {s.fileno(): s for s in (self.s_rtr, self.s_wan)}
        while True:
            ready = poll.poll()
            for fd, event in ready:
                self.on_poll_event(socks[fd], event)

    def on_poll_event(self, sock_in, event):
        log = self.log
        ifname = getifname(sock_in)
        if event != select.POLLIN:
            ename = self._poll_events.get(event, "???")
            raise IOError(
                "[%s] Unexpected poll event: %s (%d)" % (ifname, ename, event)
            )

        buf = sock_in.recv(2048)

        if self.args.debug_packets:
            log.debug("%s: Received %d bytes:\n%s", ifname, len(buf), strbuf(buf))

        eap = EAPFrame.from_buf(buf)
        log.debug("%s: %s", ifname, eap)

        if sock_in == self.s_rtr:
            sock_out = self.s_wan
        else:
            sock_out = self.s_rtr

        log.info("%s: %s > %s", ifname, eap, getifname(sock_out))
        nbytes = sock_out.send(buf)
        log.debug("%s: Sent %d bytes", getifname(sock_out), nbytes)


# Main


def parse_args():
    p = argparse.ArgumentParser("eap_proxy")

    # Interface
    p.add_argument("if_wan", metavar="IF_WAN", help="ONT Interface")
    p.add_argument("if_rtr", metavar="IF_ROUTER", help="Gateway/Router Interface")

    # Process
    g = p.add_argument_group("Process management")
    g.add_argument(
        "--daemon",
        action="store_true",
        help="Run in background until killed; implies --syslog"
    )
    g.add_argument(
        "--pidfile",
        help="Record PID to PIDFILE"
    )
    g.add_argument(
        "--syslog",
        action="store_true",
        help="Log to syslog instead of stderr"
    )
    g.add_argument(
        "--run-as",
        metavar="USER[:GROUP]",
        help="Switch to USER[:GROUP] after opening sockets; "
        "incompatible with --daemon",
    )

    # Debug
    g = p.add_argument_group("Debugging")
    g.add_argument(
        "--promiscuous",
        action="store_true",
        help="Place interface into promiscuous mode instead of multicast",
    )
    g.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    g.add_argument(
        "--debug-packets",
        action="store_true",
        help="Print packets in hex format to assist with debugging; "
        "implies --debug",
    )

    args = p.parse_args()
    if args.run_as:
        if args.daemon:
            p.error("--run-as is not allowed with --daemon")
        user, __, group = args.run_as.partition(":")
        args.run_as = (user, group)
    if args.daemon:
        args.syslog = True
    if args.debug_packets:
        if args.syslog:
            p.error("--debug-packets is not allowed with --syslog")
        args.debug = True
    return args


def proxy_loop(args, log):
    proxy = EAPProxy(args, log)
    if args.run_as:
        try:
            run_as(*args.run_as)
            log.debug("Running as UID:GID %d:%d" % (os.getuid(), os.getgid()))
        except Exception:
            log.exception("Could not switch UID/GID: %s", strexc())
            return 1
    log.info("Starting proxy_loop")
    proxy.proxy_loop()
    return 0


def proxy_loop_forever(args, log):
    while True:
        try:
            proxy_loop(args, log)
        except KeyboardInterrupt:
            return 0
        except Exception as ex:
            log.warn("WARNING: %s; restarting in 30 seconds", strexc(), exc_info=ex)
        else:
            log.warn("WARNING: proxy_loop exited; restarting in 30 seconds")
        time.sleep(30)


def main():
    args = parse_args()
    log = make_logger(args.syslog, args.debug)

    if args.pidfile:
        pid = checkpidfile(args.pidfile)
        if pid:
            log.error("Could not start, already running with PID %s", pid)
            return 1

    if args.daemon:
        try:
            daemon()
        except Exception:
            log.exception("Could not start daemon: %s", strexc())
            return 1

    # SIGTERM
    def on_sigterm(signum, __):
        log.info("Exiting on signal %d", signum)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, on_sigterm)

    if args.pidfile:
        try:
            writepidfile(args.pidfile)
        except EnvironmentError:
            log.exception("Could not write PIDFILE: %s", strexc())

    proxy = proxy_loop_forever if args.daemon else proxy_loop
    return proxy(args, log)


if __name__ == "__main__":
    sys.exit(main())
