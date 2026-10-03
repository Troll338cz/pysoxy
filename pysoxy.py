#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 Small Socks5 Proxy Server in Python
 from https://github.com/MisterDaneel/
"""

# Network
import socket
import select
from struct import pack, unpack, error as struct_error
# System
import traceback
from threading import Thread, active_count
from signal import signal, SIGINT, SIGTERM
from time import sleep
import sys
import os

#
# Configuration
#
MAX_THREADS = 200
BUFSIZE = 2048
TIMEOUT_SOCKET = 5
LOCAL_ADDR = '127.0.0.1'
LOCAL_PORT = 9050
# Parameter to bind a socket to a device, using SO_BINDTODEVICE
# Only root can set this option
# If the name is an empty string or None, the interface is chosen when
# a routing decision is made
# OUTGOING_INTERFACE = "eth0"
OUTGOING_INTERFACE = ""
# SOCKS5 Basic Authentication (type 0x02)
AUTH_ENABLE = True
AUTH_USER = ""
AUTH_PASS = ""

#
# Constants
#
'''Version of the protocol'''
# PROTOCOL VERSION 5
VER = b'\x05'
'''Method constants'''
# '00' NO AUTHENTICATION REQUIRED
M_NOAUTH = b'\x00'
# '02' BASIC AUTHENTICATION
M_AUTHBASIC = b'\x02'
# 'FF' NO ACCEPTABLE METHODS
M_NOTAVAILABLE = b'\xff'
'''Command constants'''
# CONNECT '01'
CMD_CONNECT = b'\x01'
'''Address type constants'''
# IP V4 address '01'
ATYP_IPV4 = b'\x01'
# DOMAINNAME '03'
ATYP_DOMAINNAME = b'\x03'
# IP V6 address '04'
ATYP_IPV6 = b'\x04'
'''Authentication status codes'''
AUTH_STATUS_OK = b'\x01\x00'
AUTH_STATUS_FAILURE = b'\x01\xff'


class ExitStatus:
    """ Manage exit status """
    def __init__(self):
        self.exit = False

    def set_status(self, status):
        """ set exist status """
        self.exit = status

    def get_status(self):
        """ get exit status """
        return self.exit


def error(msg="", err=None):
    """ Print exception stack trace python """
    if msg:
        traceback.print_exc()
        if isinstance(err, tuple) and len(err) >= 2:
            print("{} - Code: {}, Message: {}".format(msg, str(err[0]), err[1]))
        elif err is not None:
            # For standard exceptions, use str(err) for the message
            print("{} - Error: {}".format(msg, str(err)))
        else:
            print(msg)
    else:
        traceback.print_exc()


def proxy_loop(socket_src, socket_dst):
    """ Wait for network activity """
    while not EXIT.get_status():
        try:
            reader, _, _ = select.select([socket_src, socket_dst], [], [], 1)
        except select.error as err:
            error("Select failed", err)
            return
        if not reader:
            continue
        try:
            for sock in reader:
                data = sock.recv(BUFSIZE)
                if not data:
                    return
                if sock is socket_dst:
                    socket_src.sendall(data)
                else:
                    socket_dst.sendall(data)
        except socket.error as err:
            error("Loop failed", err)
            return


def connect_to_dst(dst_addr, dst_port, socket_family):
    """ Connect to desired destination """
    sock = create_socket(socket_family)
    if OUTGOING_INTERFACE:
        sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_BINDTODEVICE,
            OUTGOING_INTERFACE.encode(),
        )
    try:
        sock.connect((dst_addr, dst_port))
        return sock
    except socket.error as err:
        error("Failed to connect to DST", err)
        return 0

def socks_get_ip_type(dst_addr, dst_port):
    """ Determine socket family to connect with. """
    family, _, _, _, sockaddr = socket.getaddrinfo(dst_addr, dst_port, type=socket.SOCK_STREAM)[0]
    return (ATYP_IPV6 if family == socket.AF_INET6 else ATYP_IPV4), sockaddr[0], sockaddr[1]

def request_client(wrapper):
    """ Client request details """
    # +-----+-----+-------+------+----------+----------+
    # | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    # +-----+-----+-------+------+----------+----------+
    try:
        s5_request = wrapper.recv(BUFSIZE)
    except ConnectionResetError:
        return None, None
    if s5_request[0:1] != VER or s5_request[2:3] != b'\x00':
        return None, None
    if s5_request[1:2] != CMD_CONNECT:
        return None, b'\x07'
    try:
        # Check VER, CMD and RSV
        if (
                s5_request[0:1] != VER or
                s5_request[1:2] != CMD_CONNECT or
                s5_request[2:3] != b'\x00'
        ):
            return False
        # IPV4
        if s5_request[3:4] == ATYP_IPV4:
            dst_addr = socket.inet_ntoa(s5_request[4:8])
            dst_port = unpack('>H', s5_request[8:10])[0]
            dst_family = ATYP_IPV4
        # DOMAIN NAME
        elif s5_request[3:4] == ATYP_DOMAINNAME:
            sz = s5_request[4]
            port_to_unpack = s5_request[5 + sz : 7 + sz]
            dst_family, dst_addr, dst_port  = socks_get_ip_type(s5_request[5 : 5 + sz], unpack('>H', port_to_unpack)[0])
        # IPv6
        elif s5_request[3:4] == ATYP_IPV6:
            dst_addr = socket.inet_ntop(socket.AF_INET6, s5_request[4:20])
            dst_port = unpack('>H', s5_request[20:22])[0]
            dst_family = ATYP_IPV6
        else:
            return None, b'\x08'
        return (dst_addr, dst_port, dst_family), b'\x00'
    except socket.gaierror:
        return None, b'\x04'
    except (IndexError, struct_error):
        return None, b'\x01'


def request(wrapper):
    """
        The SOCKS request information is sent by the client as soon as it has
        established a connection to the SOCKS server, and completed the
        authentication negotiations.  The server evaluates the request, and
        returns a reply
    """
    target, rep = request_client(wrapper)
    if rep is None:
        return
    socket_dst = 0
    reply = VER + rep + b'\x00\x01' + b'\x00' * 6
    try:
        if target:
            socket_dst = connect_to_dst(*target)
            if socket_dst != 0:
                rep = b'\x00'
                host, port = socket_dst.getsockname()[:2]
                if target[2] == ATYP_IPV6:
                    bnd = socket.inet_pton(socket.AF_INET6, host.split('%')[0])
                    reply = VER + rep + b'\x00' + ATYP_IPV6 + bnd + pack('>H', port)
                else:
                    reply = VER + rep + b'\x00' + ATYP_IPV4 + socket.inet_aton(host) + pack('>H', port)
            else:
                rep = b'\x05'
                reply = VER + rep + b'\x00\x01' + b'\x00' * 6
        wrapper.sendall(reply)
        if rep == b'\x00':
            proxy_loop(wrapper, socket_dst)
    finally:
        if socket_dst != 0:
            socket_dst.close()

def subnegotiation_client(wrapper):
    """
        The client connects to the server, and sends a version
        identifier/method selection message
    """
    # Client Version identifier/method selection message
    # +-----+----------+----------+
    # | VER | NMETHODS | METHODS  |
    # +-----+----------+----------+
    try:
        identification_packet = wrapper.recv(BUFSIZE)
    except socket.error:
        error()
        return M_NOTAVAILABLE
    # VER field
    if VER != identification_packet[0:1]:
        return M_NOTAVAILABLE
    # METHODS fields
    nmethods = identification_packet[1]
    methods = identification_packet[2:]
    if len(methods) != nmethods:
        return M_NOTAVAILABLE
    # Enforce only one supported method
    for method in methods:
        if method == ord(M_NOAUTH) and not AUTH_ENABLE:
            return M_NOAUTH
        if method == ord(M_AUTHBASIC) and AUTH_ENABLE:
            return M_AUTHBASIC
    return M_NOTAVAILABLE

def subnegotiation_auth(wrapper):
    """
        Parse basic auth packet
    """
    # +-----+----------+------+----------+------+
    # | VER | User LEN | User | Pass LEN | Pass |
    # +-----+----------+------+----------+------+

    try:
        auth_packet = wrapper.recv(BUFSIZE)
    except socket.error:
        error()
        return AUTH_STATUS_FAILURE

    # Too short
    if len(auth_packet) < 2:
        return AUTH_STATUS_FAILURE

    # Wrong version
    if auth_packet[0] != 1:
        return AUTH_STATUS_FAILURE

    ulen = auth_packet[1]
    offset = 2

    # Len check #1
    if len(auth_packet) < offset + ulen + 1:
        return AUTH_STATUS_FAILURE

    username = auth_packet[offset:offset + ulen]
    offset += ulen

    plen = auth_packet[offset]
    offset += 1

    # Len check #2
    if len(auth_packet) < offset + plen:
        return AUTH_STATUS_FAILURE

    password = auth_packet[offset:offset + plen]

    if username.decode('utf-8', errors="replace") == AUTH_USER and password.decode('utf-8', errors="replace") == AUTH_PASS:
           return AUTH_STATUS_OK

    return AUTH_STATUS_FAILURE

def subnegotiation(wrapper):
    """
        The client connects to the server, and sends a version
        identifier/method selection message
        The server selects from one of the methods given in METHODS, and
        sends a METHOD selection message
    """
    method = subnegotiation_client(wrapper)
    # Server Method selection message
    # +-----+--------+
    # | VER | METHOD |
    # +-----+--------+
    reply = b''
    if method == M_NOAUTH or method == M_AUTHBASIC or method == M_NOTAVAILABLE:
        reply = VER + method
    else:
        return False

    try:
        wrapper.sendall(reply)
    except socket.error:
        error()
        return False

    if method == M_AUTHBASIC:
        reply = subnegotiation_auth(wrapper)
        try:
            wrapper.sendall(reply)
        except socket.error:
            error()
            return False

    if method == M_NOTAVAILABLE or reply == AUTH_STATUS_FAILURE:
        return False

    return True


def connection(wrapper):
    """ Function run by a thread """
    try:
        if subnegotiation(wrapper):
            request(wrapper)
    except Exception:
        error()
    finally:
        wrapper.close()

def create_socket(socket_family):
    """ Create an INET, STREAMing socket """
    try:
        if socket_family == ATYP_IPV6:
           sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
           sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_SOCKET)
    except socket.error as err:
        error("Failed to create socket", err)
        sys.exit(1)
    return sock


def bind_port(sock):
    """
        Bind the socket to address and
        listen for connections made to the socket
    """
    try:
        print('Bind {}'.format(str(LOCAL_PORT)))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((LOCAL_ADDR, LOCAL_PORT))
    except socket.error as err:
        error("Bind failed", err)
        sock.close()
        sys.exit(1)
    # Listen
    try:
        sock.listen(10)
    except socket.error as err:
        error("Listen failed", err)
        sock.close()
        sys.exit(1)
    return sock


def exit_handler(signum, frame):
    """ Signal handler called with signal, exit script """
    print('Signal handler called with signal', signum)
    EXIT.set_status(True)


def main():
    """ Main function """
    if OUTGOING_INTERFACE and os.getuid() != 0:
        print("Only root can run with OUTGOING_INTERFACE parameter set.")
        sys.exit(1)

    if AUTH_ENABLE and not ( len(AUTH_USER) and len(AUTH_PASS) ):
        print("Authentication enabled but no login set, quitting.")
        sys.exit(1)

    new_socket = create_socket(ATYP_IPV4)
    bind_port(new_socket)
    signal(SIGINT, exit_handler)
    signal(SIGTERM, exit_handler)
    
    while not EXIT.get_status():
        if active_count() > MAX_THREADS:
            sleep(3)
            continue
        try:
            wrapper, _ = new_socket.accept()
            wrapper.settimeout(30)
        except socket.timeout:
            continue
        except socket.error:
            error()
            continue
        except TypeError:
            error()
            sys.exit(1)
        recv_thread = Thread(target=connection, args=(wrapper, ))
        recv_thread.start()
    new_socket.close()


EXIT = ExitStatus()
if __name__ == '__main__':
    main()
