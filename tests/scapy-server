#!/usr/bin/env python3

import argparse

import ovs.daemon
import ovs.unixctl
import ovs.unixctl.server

import binascii
from scapy.all import *  # noqa: F401,F403
from scapy.all import raw


vlog = ovs.vlog.Vlog("scapy-server")
exiting = False


def exit(conn, argv, aux):
    global exiting

    exiting = True
    conn.reply(None)


def process(data):
    try:
        data = data.replace('\n', '')
        return binascii.hexlify(raw(eval(data))).decode()
    except Exception:
        return ""


def payload(conn, argv, aux):
    conn.reply(process(argv[0]))


def main():
    parser = argparse.ArgumentParser(
        description="Scapy-based Frame Payload Generator")
    parser.add_argument("--unixctl", help="UNIXCTL socket location or 'none'.")

    ovs.daemon.add_args(parser)
    ovs.vlog.add_args(parser)
    args = parser.parse_args()
    ovs.daemon.handle_args(args)
    ovs.vlog.handle_args(args)

    ovs.daemon.daemonize_start()
    error, server = ovs.unixctl.server.UnixctlServer.create(args.unixctl)
    if error:
        ovs.util.ovs_fatal(error, "could not create unixctl server at %s"
                           % args.unixctl, vlog)

    ovs.unixctl.command_register("exit", "", 0, 0, exit, None)
    ovs.unixctl.command_register("payload", "", 1, 1, payload, None)
    ovs.daemon.daemonize_complete()

    poller = ovs.poller.Poller()
    while not exiting:
        server.run()
        server.wait(poller)
        if exiting:
            poller.immediate_wake()
        poller.block()
    server.close()


if __name__ == '__main__':
    main()
