#!/usr/bin/env python3

import click
from aiohttp import web
from wakeonlan import send_magic_packet
from netaddr import EUI
from ipaddress import ip_address, ip_network


WHITELIST = []


async def handle(request):
    if len(WHITELIST) > 0:
        if not any(ip_address(request.remote) in network for network in WHITELIST):
            print(f"Refused conn from {request.remote}, not in a whitelist")
            return web.Response(status=403)

    mac = request.match_info.get('mac')
    formatted_mac = str(EUI(mac)).replace('-', '.')

    print(f"Sending magic packet to: {formatted_mac}")
    send_magic_packet(formatted_mac)

    return web.Response(status=200)


def app():
    app = web.Application()
    app.add_routes([
        web.get('/{mac}', handle)
    ])
    return app


@click.command()
@click.option('--host', default='localhost', help='host IP address')
@click.option('--port', default=9090, help='bind to given port')
@click.option('--whitelist', default=['127.0.0.1/32'], multiple=True, help='allow requests from given IP whitelist')
def run(host, port, whitelist):
    global WHITELIST
    WHITELIST = [ip_network(network) for network in whitelist]
    web.run_app(app(), host=host, port=port)


if __name__ == '__main__':
    run()
