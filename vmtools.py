# Copyright (c) 2011-2012, Mark Peek <mark@peek.org>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met: 
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution. 
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import _vmt
import atexit
import platform
import time
import os


# RPC Channels
CHANNEL_RPCI = 0x49435052
CHANNEL_TCLO = 0x4f4c4354

CMD_PING = "ping"
CMD_PING0 = "ping\x00"
CMD_RESET = "reset"
CMD_CAPA = "Capabilities_Register"
CMD_OSSUSPEND = "OS_Suspend"
CMD_OSRESUME = "OS_Resume"
CMD_OSREBOOT = "OS_Reboot"
CMD_OSHALT = "OS_Halt"
CMD_TIMESYNC = "Set_Option time.synchronize.tools.enable 1"
CMD_BROADCASTIP = "Set_Option broadcastIP 1"
CMD_AFTERPOWERON = "Set_Option toolScripts.afterPowerOn 1"
CMD_BEFOREPOWEROFF = "Set_Option toolScripts.beforePowerOff 1"
CMD_BEFORESUSPEND = "Set_Option toolScripts.beforeSuspend 1"
CMD_AFTERRESUME = "Set_Option toolScripts.afterResume 1"

MESSAGE_SUCCESS    = 0x0001
MESSAGE_DORECV     = 0x0002
MESSAGE_CLOSED     = 0x0004
MESSAGE_UNSENT     = 0x0008
MESSAGE_CHECKPT    = 0x0010
MESSAGE_POWEROFF   = 0x0020
MESSAGE_TIMEOUT    = 0x0040
MESSAGE_HB_SUPPORT = 0x0080

MESSAGE_COOKIE = 0x80000000

MESSAGE_TYPE_OPEN        = 0x00000000
MESSAGE_TYPE_SENDSIZE    = 0x00010000
MESSAGE_TYPE_SENDPAYLOAD = 0x00020000
MESSAGE_TYPE_RECVSIZE    = 0x00030000
MESSAGE_TYPE_RECVPAYLOAD = 0x00040000
MESSAGE_TYPE_RECVSTATUS  = 0x00050000
MESSAGE_TYPE_CLOSE       = 0x00060000

RPC_PORT = 0x5659

noaction = False
verbose = False

class channel(object):
    def __init__(self, proto):
        self.proto = proto
        self.v = _vmt.vmt()
        self.id = None
        self.cookieHigh = 0
        self.cookieLow = 0
        # Cache the _vmt variables for shutdown when the module goes away
        self.VM_BACKDOOR_PORT = _vmt.VM_BACKDOOR_PORT
        self.VM_CMD = _vmt.VM_CMD
        self.VM_MAGIC = _vmt.VM_MAGIC
        self._open_channel()

    def __del__(self):
        self._close_channel()
        pass

    def _message_success(self, rcx):
        return ((rcx & 0xffff0000) >> 16) == MESSAGE_SUCCESS

    def _open_channel(self):
        self.v.rax = self.VM_MAGIC
        self.v.rbx = self.proto | MESSAGE_COOKIE
        self.v.rcx = MESSAGE_TYPE_OPEN | self.VM_CMD
        self.v.rdx = self.VM_BACKDOOR_PORT
        self.v.backdoor()
        if self._message_success(self.v.rcx):
            self.id = self.v.rdx & 0xffff0000
            self.cookieHigh = self.v.rsi
            self.cookieLow = self.v.rdi
        else:
            print "could not open channel"

    def _close_channel(self):
        if self.id is None:
            return
        self.v.rax = self.VM_MAGIC
        self.v.rbx = 0
        self.v.rcx = MESSAGE_TYPE_CLOSE | self.VM_CMD
        self.v.rdx = self.id | self.VM_BACKDOOR_PORT
        self.v.rsi = self.cookieHigh
        self.v.rdi = self.cookieLow
        self.v.backdoor()
        self.id = None

    def send(self, s):
        if self.id is None:
            return

        # Send the length first
        self.v.rax = self.VM_MAGIC
        self.v.rbx = len(s)
        self.v.rcx = MESSAGE_TYPE_SENDSIZE | self.VM_CMD
        self.v.rdx = self.id | self.VM_BACKDOOR_PORT
        self.v.rsi = self.cookieHigh
        self.v.rdi = self.cookieLow
        self.v.backdoor()

        if len(s):
            # Send the command
            self.v.rax = self.VM_MAGIC
            self.v.rbx = 0x00010000 # really bdoorhb_cmd_message | message_status_success
            self.v.rcx = len(s)
            self.v.rdx = self.id | RPC_PORT
            self.v.rbp = self.cookieHigh
            self.v.rdi = self.cookieLow
            self.v.backdoor_send(s)

    def receive(self):
        if self.id is None:
            return

        # Get the length first
        self.v.rax = self.VM_MAGIC
        self.v.rbx = 0
        self.v.rcx = MESSAGE_TYPE_RECVSIZE | self.VM_CMD
        self.v.rdx = self.id | self.VM_BACKDOOR_PORT
        self.v.rsi = self.cookieHigh
        self.v.rdi = self.cookieLow
        self.v.backdoor()
        length = self.v.rbx

        # Check if there is anything to return
        if not ((self.v.rcx & 0xffff000) >> 16) & MESSAGE_DORECV:
            return ""

        # Receive the buffer back
        self.v.rax = self.VM_MAGIC
        #self.v.rbx = MESSAGE_TYPE_RECVPAYLOAD | self.VM_CMD
        self.v.rbx = 0x00010000
        self.v.rcx = length
        #self.v.rdx = self.id | self.VM_RPC_PORT
        self.v.rdx = self.id | RPC_PORT
        self.v.rsi = self.cookieHigh
        self.v.rbp = self.cookieLow
        ret = self.v.backdoor_recv(length)

        # Ack receive
        self.v.rax = self.VM_MAGIC
        self.v.rbx = MESSAGE_SUCCESS
        self.v.rcx = MESSAGE_TYPE_RECVSTATUS | self.VM_CMD
        self.v.rdx = self.id | self.VM_BACKDOOR_PORT
        self.v.rsi = self.cookieHigh
        self.v.rdi = self.cookieLow
        self.v.backdoor()

        return ret
        
class rpc_channel(object):
    def __init__(self):
        self.channel = channel(CHANNEL_RPCI)

    def rpc(self, s):
        if verbose:
            print "RPC sending: %s" % (s,)
        self.channel.send(s)
        ret = self.channel.receive()
        if verbose:
            print "RPC received: %s" % (ret,)
        return ret

class tclo_channel(object):
    def __init__(self):
        self.channel = channel(CHANNEL_TCLO)

    def receive(self):
        ret = self.channel.receive()
        if verbose:
            print "TCLO received: %s" % (ret,)
        return ret

    def send(self, s):
        if verbose:
            print "TCLO sending: %s" % (s,)
        self.channel.send(s)

def cleanup(chan, msg):
    if verbose:
        print "cleaning up"
    chan.send(msg)

def cmd_ok(rpc, tclo):
    return 1

def cmd_reset(rpc, tclo):
    tclo.send("OK ATR toolbox");
    return 0

def cmd_capa(rpc, tclo):
    rpc.rpc("vmx.capability.unified_loop toolbox")
    rpc.rpc("tools.capability.statechange ")
    rpc.rpc("tools.capability.softpowerop_retry ")
    # Fake a version
    rpc.rpc("tools.set.version 2147483647")
    return 1

def cmd_ossuspend(rpc, tclo):
    if verbose:
        print "Suspending..."
    time.sleep(5)
    tclo.send("OK ")
    time.sleep(5)
    rpc.rpc("tools.os.statechange.status 1 5")
    return 0

def cmd_osresume(rpc, tclo):
    if verbose:
        print "Resuming..."
    # XXX - should these be reversed?
    tclo.send("OK ")
    rpc.rpc("tools.os.statechange.status 1 4")
    return 0

def cmd_osreboot(rpc, tclo):
    if verbose:
        print "Rebooting..."
    time.sleep(30)
    if not noaction:
        os.system("/sbin/shutdown -r now")

def cmd_oshalt(rpc, tclo):
    if verbose:
        print "Halting..."
    time.sleep(10)
    if not noaction:
        print platform.system
        if platform.system() == 'FreeBSD':
            print "FreeBSD...shutdown"
            os.system("/sbin/shutdown -p now")
        elif platform.system() == 'Linux':
            os.system("/sbin/shutdown -h now")
        else:
            os.system("halt -p")

def cmd_broadcastip(rpc, tclo):
    # Need to provide an interface to set the IP address correctly
    rpc.rpc("info-set guestinfo.ip 127.0.0.1 ")
    return 1

commands = {
    CMD_PING: cmd_ok,
    CMD_PING0: cmd_ok,
    CMD_RESET: cmd_reset,
    CMD_CAPA: cmd_capa,
    CMD_AFTERPOWERON: cmd_ok,
    CMD_BEFOREPOWEROFF: cmd_ok,
    CMD_BEFORESUSPEND: cmd_ok,
    CMD_AFTERRESUME: cmd_ok,
    CMD_TIMESYNC: cmd_ok,
    CMD_OSSUSPEND: cmd_ossuspend,
    CMD_OSREBOOT: cmd_osreboot,
    CMD_OSHALT: cmd_oshalt,
    CMD_OSRESUME: cmd_osresume,
    CMD_BROADCASTIP: cmd_broadcastip,
}

class vmclient(object):
    def __init__(self, sleeper=None):
        # Open the RPC channels
        self.tclo = tclo_channel()
        self.rpc = rpc_channel()
        self.tclo.send("OK ATR toolbox")
        self.uptime = 437498623
        self.sleeper = sleeper

    def close(self):
        self.tclo.send("tools.capability.hgfs_server toolbox 0")

    def poller(self):
        cmd = self.tclo.receive()
        if cmd == "":
            if self.sleeper is None:
                # Nothing to see here...move on
                time.sleep(5)
            else:
                self.sleeper()
            self.uptime = self.uptime + 5
            if self.uptime % 100 == 0:
                self.rpc("SetGuestInfo  7 %d" % (self.uptime,))
            self.tclo.send("")
        elif cmd in commands:
            # Dispatch command
            if commands[cmd](self.rpc, self.tclo):
                self.tclo.send("OK ")
        else:
            if verbose:
                print "Sending error for '%s'" % (cmd, )
            self.tclo.send("ERROR Unknown command")

def sleeper():
    time.sleep(10)

def main():
    global verbose, noaction
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("-n", action="store_true", dest="noaction", default=False)
    parser.add_option("-v", action="store_true", dest="verbose", default=False)
    (options, args) = parser.parse_args()
    noaction = options.noaction
    verbose = options.verbose

    vmc = vmclient(sleeper)
    try:
        while 1:
            vmc.poller()
    except KeyboardInterrupt:
        pass
    vmc.close()

if __name__ == "__main__":
    main()
