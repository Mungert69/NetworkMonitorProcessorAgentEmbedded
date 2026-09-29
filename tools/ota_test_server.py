#!/usr/bin/env python3
"""Serve signed firmware over HTTPS for local emulator OTA tests only."""

import argparse
import http.server
import pathlib
import ssl


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=pathlib.Path, required=True)
    parser.add_argument("--cert", type=pathlib.Path, required=True)
    parser.add_argument("--key", type=pathlib.Path, required=True)
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    directory = args.directory.resolve()

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *handler_args, **handler_kwargs):
            super().__init__(*handler_args, directory=str(directory), **handler_kwargs)

        def do_GET(self):
            if self.path != "/networkmonitor_processor_esp32.bin":
                self.send_error(404)
                return
            super().do_GET()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
