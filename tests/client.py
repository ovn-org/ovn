#!/usr/bin/env python3

import socket
import time
import argparse
import datetime
import os


def log_error(message):
    """Log error messages to <script_name>.log file"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] CLIENT ERROR: {message}\n"

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


def send_data_from_fifo_to_server(fifo_path='/tmp/myfifo',
                                  host='127.0.0.1', port=10000):
    # Determine socket family based on host address
    family = get_socket_family(host)

    try:
        # Open the FIFO for reading (blocking mode)
        with open(fifo_path, 'r') as fifo_file:
            with socket.socket(family, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((host, port))
                while True:
                    data = fifo_file.readline()
                    if data:
                        client_socket.sendall(data.encode())
                    else:
                        time.sleep(0.1)

    except FileNotFoundError as e:
        log_error(f"FIFO file not found: {fifo_path} - {e}")
        raise
    except Exception as e:
        log_error(f"Unexpected error in client: {e}")
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    group = parser.add_argument_group()
    group.add_argument("-f", "--fifo_path")
    group.add_argument("-i", "--server-host")
    group.add_argument("-p", "--server-port", type=int)
    args = parser.parse_args()

    send_data_from_fifo_to_server(
        args.fifo_path, args.server_host, args.server_port
    )
