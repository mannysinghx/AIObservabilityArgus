"""Dual-stack uvicorn launcher.

Why this exists (Railway networking): Railway's health-check probe reaches a
service over IPv4, while its private network (worker -> detection) is IPv6-only.
A plain `uvicorn --host ::` binds an IPv6-*only* socket in Railway's runtime
(IPV6_V6ONLY defaults to 1 there), so the IPv4 health check fails even though
the worker can reach it over IPv6.

We instead create one explicit dual-stack socket (IPV6_V6ONLY=0) bound to `::`,
which accepts both IPv4 (health check, via IPv4-mapped addresses) and IPv6
(private networking). Locally under docker-compose this also works — the
dual-stack socket accepts the IPv4 connections Docker's service DNS resolves to.
"""
from __future__ import annotations

import os
import socket

import uvicorn


def _dual_stack_socket(port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # The crucial line: allow IPv4 connections on this IPv6 socket.
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(("::", port))
    sock.listen(128)
    return sock


def main() -> None:
    port = int(os.environ.get("PORT", "8000"))
    sock = _dual_stack_socket(port)
    config = uvicorn.Config("argus_detection.app:app", fd=sock.fileno(), log_level="info")
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
