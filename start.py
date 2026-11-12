#!/usr/bin/env python3
"""
start.py - one-step launcher for dweb-gateway.

Run this file and nothing else: it picks a free port, starts the gateway, and opens the
guided view in your browser. No arguments, no setup, no terminal knowledge needed.

    python3 start.py          (or double-click run.bat on Windows / run.sh on macOS-Linux)
"""

import os
import socket
import sys
import threading
import time
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

try:
    import dweb_gateway as gw
except ImportError as err:
    print("\n  Could not load dweb_gateway.py from this folder: %s\n" % err)
    print("  Keep start.py, dweb_gateway.py, simple.html and webui.html together.\n")
    sys.exit(1)


def free_port(preferred=8787):
    for port in (preferred, 8788, 8789, 8790, 0):
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.bind(("127.0.0.1", port))
            found = probe.getsockname()[1]
            probe.close()
            return found
        except OSError:
            continue
    return 0


def main():
    port = free_port()
    httpd, store, root_cid = gw.build_server(
        port,
        os.path.join(HERE, "store"),
        os.path.join(HERE, "webui.html"),
        simple_path=os.path.join(HERE, "simple.html"),
    )
    port = httpd.server_address[1]
    url = "http://127.0.0.1:%d/" % port
    base = url.rstrip("/")

    print("\n  dweb-gateway is running.")
    print("  ------------------------------------------------")
    print("  Guided view     %s" % url)
    print("  Technical view  %s/panel" % base)
    print("  Blocks stored   %d" % len(store.all_cids()))
    if root_cid:
        print("  Example site    %s/ipfs/%s/" % (base, root_cid))
    print("\n  Your browser should open by itself. If it does not, paste the")
    print("  guided view address above into it. Close this window to stop.\n")

    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    def open_later():
        time.sleep(0.8)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    threading.Thread(target=open_later, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  stopped\n")
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    main()
