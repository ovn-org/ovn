#!/usr/bin/env python3
# Copyright (c) 2020 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Simple python script which connects to tcp server and then
# resets the connection.
import argparse
import socket
import struct
import time

parser = argparse.ArgumentParser(description='')
parser.add_argument("--src-port", type=int, default=11337,
                    help="source port to use")
parser.add_argument("--dst-port", type=int, help="dst port to use")
parser.add_argument("--dst-ip", help="server ip to use")
args = parser.parse_args()
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = (args.dst_ip, args.dst_port)
sock.bind(('0.0.0.0', args.src_port))
sock.connect(server_address)
l_onoff = 1
l_linger = 0
time.sleep(1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                struct.pack('ii', l_onoff, l_linger))
sock.close()
