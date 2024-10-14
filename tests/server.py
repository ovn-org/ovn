#!/usr/bin/env python3

import socket
import argparse


def start_server(host='127.0.0.1', port=10000):
    # Create a TCP/IP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        with open("output.txt", "a") as f:
            f.write("Server Ready\n")
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
