"""Loopback-only synthetic controller for the real engine protocol acceptance.
Not a production launcher. Writes only inside the caller's temporary directory.
"""
import hashlib
import json
from pathlib import Path
import ssl
import sys
import time

from aiohttp import web
from services.antifraud import Controller,initialize
from services.antifraud_api import Authenticator,create_app
from tests.test_traffic_observation import inventory,sample

async def main(directory):
    root=Path(directory)
    db=root/'controller.db';at=time.time_ns()//1000000
    initialize(db,inventory(),at-1000)
    with Controller(db) as c:
        c.observe([sample(m,0,at-1000,0) for m in ('a1','a2','b1')],at-1000)
        c.observe([sample('a1',1,at,20_000_000_000)],at)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(root/'server.pem',root/'server.key');context.load_verify_locations(root/'ca.pem');context.verify_mode=ssl.CERT_OPTIONAL
    # Synthetic credential exists only for this ephemeral fixture.
    admin='local-fixture-admin-'+'a'*48
    auth=Authenticator(admin_sha256=hashlib.sha256(admin.encode()).hexdigest(),notifier_sha256=hashlib.sha256(b'fixture-notifier-b').hexdigest())
    runner=web.AppRunner(create_app(db,auth),access_log=None);await runner.setup()
    site=web.TCPSite(runner,'127.0.0.1',0,ssl_context=context);await site.start()
    print(json.dumps({'origin':'https://127.0.0.1:'+str(site._server.sockets[0].getsockname()[1])}),flush=True)
    import asyncio
    try:await asyncio.Event().wait()
    finally:await runner.cleanup()

if __name__=='__main__':
    import asyncio
    asyncio.run(main(sys.argv[1]))
