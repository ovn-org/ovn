#!/usr/bin/env python3
import argparse
import string


def strip(val):
    """Strip whitespace and quotation marks from val"""
    return val.strip(f"{string.whitespace}\"'")


def parse_acl_log(line):
    """Convert an ACL log string into a dict"""
    # First cut off the logging preamble.
    # We're assuming the default log format.
    acl_log = {}
    _, _, details = line.rpartition("|")

    # acl_details are things like the acl name, direction,
    # verdict, and severity. packet_details are things like
    # the protocol, addresses, and ports of the packet being
    # logged.
    acl_details, _, packet_details = details.partition(":")
    for datum in acl_details.split(","):
        name, _, value = datum.rpartition("=")
        acl_log[strip(name)] = strip(value)

    for datum in packet_details.split(","):
        name, _, value = datum.rpartition("=")
        if not name:
            # The protocol is not preceded by "protocol="
            # so we need to add it manually.
            name = "protocol"
        acl_log[strip(name)] = strip(value)

    return acl_log


def get_acl_log(entry_num=1):
    with open("ovn-controller.log", "r") as controller_log:
        acl_logs = [line.rstrip() for line in controller_log
                    if "acl_log" in line]
        try:
            return acl_logs[entry_num - 1]
        except IndexError:
            print(
                f"There were not {entry_num} acl_log entries, "
                f"only {len(acl_logs)}"
            )
            exit(1)


def add_parser_args(parser):
    parser.add_argument("--entry-num", type=int, default=1)

    # There are other possible things that can be in an ACL log,
    # and if we need those in the future, we can add them later.
    parser.add_argument("--name")
    parser.add_argument("--verdict")
    parser.add_argument("--severity")
    parser.add_argument("--protocol")
    parser.add_argument("--vlan_tci")
    parser.add_argument("--dl_src")
    parser.add_argument("--dl_dst")
    parser.add_argument("--nw_src")
    parser.add_argument("--nw_dst")
    parser.add_argument("--nw_tos")
    parser.add_argument("--nw_ecn")
    parser.add_argument("--nw_ttl")
    parser.add_argument("--icmp_type")
    parser.add_argument("--icmp_code")
    parser.add_argument("--tp_src")
    parser.add_argument("--tp_dst")
    parser.add_argument("--tcp_flags")
    parser.add_argument("--ipv6_src")
    parser.add_argument("--ipv6_dst")


def main():
    parser = argparse.ArgumentParser()
    add_parser_args(parser)
    args = parser.parse_args()

    acl_log = get_acl_log(args.entry_num)
    parsed_log = parse_acl_log(acl_log)

    # Express command line arguments as a dict, omitting any arguments that
    # were not provided by the user.
    expected = {k: v for k, v in vars(args).items() if v is not None}
    del expected["entry_num"]

    for key, val in expected.items():
        try:
            if parsed_log[key] != val:
                print(
                    f"Expected log {key}={val} but got "
                    f"{key}={parsed_log[key]} "
                    f"in:\n\t'{acl_log}'"
                )
                exit(1)
        except KeyError:
            print(
                f"Expected log {key}={val} but {key} does not exist in:\n"
                f"\t'{acl_log}'"
            )
            exit(1)


if __name__ == "__main__":
    main()
