#!/usr/bin/env python3

import socket
import argparse
import datetime
import os


def log_error(message):
    """Log error messages to <script_name>.log file"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] SERVER ERROR: {message}\n"

    try:
        script_name = os.path.basename(__file__)
        log = f"{script_name}.log"
        with open(log, "a") as log_file:
            log_file.write(log_message)
    except:
        pass


def get_socket_family(host):
    """Determine socket family based on IP address format"""
    try:
        # Try to parse as IPv4
        socket.inet_aton(host)
        return socket.AF_INET
    except socket.error:
        try:
            # Try to parse as IPv6
            socket.inet_pton(socket.AF_INET6, host)
            return socket.AF_INET6
        except socket.error:
            raise


def start_server(host='127.0.0.1', port=10000):
    # Determine socket family based on host address
    family = get_socket_family(host)

    # Create a TCP socket with appropriate family
    with socket.socket(family, socket.SOCK_STREAM) as server_socket:
        if family == socket.AF_INET6:
            # For IPv6, disable dual-stack to avoid conflicts
            server_socket.setsockopt(socket.IPPROTO_IPV6,
                                     socket.IPV6_V6ONLY, 1)
            # Allow address reuse for IPv6
            server_socket.setsockopt(socket.SOL_SOCKET,
                                     socket.SO_REUSEADDR, 1)
        else:
            # Allow address reuse for IPv4
            server_socket.setsockopt(socket.SOL_SOCKET,
                                     socket.SO_REUSEADDR, 1)

        try:
            # Try standard binding first
            server_socket.bind((host, port))
        except OSError as e:
            # Cannot assign requested address
            if family == socket.AF_INET6 and e.errno == 99:
                # For IPv6, try fallback to all interfaces
                log_error(f"Standard IPv6 binding failed for "
                          f"{host}:{port} - {e}. "
                          f"Trying fallback to all IPv6 interfaces")
                try:
                    server_socket.bind(('::', port))
                except OSError as e2:
                    log_error(f"Fallback binding also failed: {e2}")
                    raise
            else:
                log_error(f"Socket binding failed for {host}:{port} - {e}")
                raise

        try:
            server_socket.listen()
            with open("output.txt", "a") as f:
                f.write("Server Ready\n")
        except Exception as e:
            log_error(f"Server listen/setup failed: {e}")
            raise

        while True:
            client_socket, client_address = server_socket.accept()
            with client_socket:
                # Receive the data from the client in chunks and write
                # to a file
                data = client_socket.recv(1024)
                while data:
                    with open("output.txt", "a") as f:
                        f.write(data.decode())
                    data = client_socket.recv(1024)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    group = parser.add_argument_group()
    group.add_argument("-i", "--bind-host")
    group.add_argument("-p", "--bind-port", type=int)
    args = parser.parse_args()

    start_server(args.bind_host, args.bind_port)
