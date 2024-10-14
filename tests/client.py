#!/usr/bin/env python3

import socket
import time
import argparse


def send_data_from_fifo_to_server(
    fifo_path='/tmp/myfifo', host='127.0.0.1', port=10000
):
    # Open the FIFO for reading (blocking mode)
    with open(fifo_path, 'r') as fifo_file:
        with socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        ) as client_socket:
            client_socket.connect((host, port))
            # Continuously read from the FIFO and send to the server
            while True:
                data = fifo_file.readline()
                if data:
                    client_socket.sendall(data.encode())
                else:
                    time.sleep(0.1)


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
