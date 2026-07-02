"""Local dev launcher — binds a DUAL-STACK socket so the console is reachable on
BOTH 127.0.0.1 (IPv4) and ::1 (IPv6, which `localhost` resolves to on Windows).

Why this exists: `uvicorn --host 127.0.0.1` is IPv4-only and `--host ::` is
IPv6-only on Windows, so whichever one you pick, a browser that resolves
`localhost` to the *other* family gets "nothing loads" (the document may load but
subresource requests to the wrong family fail). Creating the socket ourselves with
IPV6_V6ONLY=0 makes a single socket accept both families.

Run from the backend/ directory:  python run_local.py
"""
import socket

import uvicorn

HOST = "::"          # dual-stack when V6ONLY is disabled below
PORT = 8000


def make_dual_stack_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    # Accept IPv4-mapped connections too (so 127.0.0.1 works alongside ::1).
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    except (AttributeError, OSError):
        pass  # platform without dual-stack support → IPv6-only fallback
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(128)
    sock.setblocking(False)
    return sock


def main() -> None:
    sock = make_dual_stack_socket()
    config = uvicorn.Config("app.main:app", log_level="info")
    server = uvicorn.Server(config)
    print(f"AEGIS console (dual-stack) on http://127.0.0.1:{PORT} and http://localhost:{PORT}")
    server.run(sockets=[sock])


if __name__ == "__main__":
    main()
