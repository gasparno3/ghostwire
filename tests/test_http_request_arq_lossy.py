#!/usr/bin/env python3.13
import asyncio
import argparse
import os
import random
import socket
import subprocess
import sys
import time
from aiohttp import ClientSession,ClientTimeout,web

def get_free_port():
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind(("127.0.0.1",0))
    port=s.getsockname()[1]
    s.close()
    return port
def write_configs(server_port,proxy_port,tunnel_port,target_port):
    token="test-token-ghostwire-arq-lossy"
    server_cfg=f"""[server]
protocol="http-request"
listen_host="127.0.0.1"
listen_port={server_port}
websocket_path="/ws"
ping_timeout=20
ws_pool_enabled=false
udp_enabled=false
auto_update=false
http_request_min_upload_ms=5
http_request_min_download_ms=10
http_request_max_upload_bytes=65536
http_request_max_download_bytes=65536
http_request_poll_min_connections=1
http_request_poll_connections=4

[auth]
token="{token}"

[tunnels]
ports=["{tunnel_port}={target_port}"]

[logging]
level="warning"
file=""
"""
    client_cfg=f"""[server]
protocol="http-request"
url="http://127.0.0.1:{proxy_port}/ws"
token="{token}"
ping_interval=5
ping_timeout=20
auto_update=false
http_request_min_upload_ms=5
http_request_min_download_ms=10
http_request_max_upload_bytes=65536
http_request_max_download_bytes=65536
http_request_poll_min_connections=1
http_request_poll_connections=4

[reconnect]
initial_delay=0.5
max_delay=3
multiplier=1.5

[cloudflare]
enabled=false
ips=[]
host=""
check_interval=300
max_connection_time=1740

[logging]
level="warning"
file=""
"""
    server_path=f"/tmp/ghostwire-arq-server-{server_port}.toml"
    client_path=f"/tmp/ghostwire-arq-client-{server_port}.toml"
    with open(server_path,"w") as f:
        f.write(server_cfg)
    with open(client_path,"w") as f:
        f.write(client_cfg)
    return server_path,client_path
async def start_payload_server(port,payload):
    async def handle(request):
        return web.Response(body=payload,content_type="application/octet-stream")
    app=web.Application()
    app.router.add_get("/payload",handle)
    runner=web.AppRunner(app,access_log=None)
    await runner.setup()
    site=web.TCPSite(runner,"127.0.0.1",port)
    await site.start()
    return runner
async def start_lossy_proxy(listen_port,upstream_port,loss_rate,disconnect_rate,delay_ms,stats):
    session=ClientSession(timeout=ClientTimeout(total=60))
    async def handle(request):
        target=f"http://127.0.0.1:{upstream_port}{request.path_qs}"
        body=await request.read()
        headers={k:v for k,v in request.headers.items() if k.lower() not in ("host","content-length")}
        try:
            async with session.request(request.method,target,data=body,headers=headers) as response:
                data=await response.read()
                stats["upstream"]+=1
                if delay_ms>0:
                    await asyncio.sleep(random.random()*delay_ms/1000.0)
                if random.random()<disconnect_rate:
                    stats["disconnects"]+=1
                    if request.transport:
                        request.transport.close()
                    return web.Response(status=499,body=b"synthetic disconnect")
                if random.random()<loss_rate:
                    stats["losses"]+=1
                    return web.Response(status=502,body=b"synthetic loss")
                response_headers={k:v for k,v in response.headers.items() if k.lower() not in ("content-length","transfer-encoding","connection")}
                return web.Response(status=response.status,headers=response_headers,body=data)
        except Exception as e:
            stats["proxy_errors"]+=1
            return web.Response(status=502,body=str(e).encode())
    app=web.Application(client_max_size=16*1024*1024)
    app.router.add_route("*","/{tail:.*}",handle)
    runner=web.AppRunner(app,access_log=None)
    await runner.setup()
    site=web.TCPSite(runner,"127.0.0.1",listen_port)
    await site.start()
    return runner,session
async def wait_for_tunnel(tunnel_port,timeout):
    deadline=time.time()+timeout
    while time.time()<deadline:
        try:
            reader,writer=await asyncio.wait_for(asyncio.open_connection("127.0.0.1",tunnel_port),timeout=1)
            writer.write(b"GET /payload HTTP/1.0\r\nHost: test\r\n\r\n")
            await writer.drain()
            data=await asyncio.wait_for(reader.read(256),timeout=2)
            writer.close()
            await writer.wait_closed()
            if b"200" in data:
                return True
        except Exception:
            pass
        await asyncio.sleep(0.2)
    return False
async def fetch_payload(tunnel_port,expected_size,timeout):
    reader,writer=await asyncio.wait_for(asyncio.open_connection("127.0.0.1",tunnel_port),timeout=timeout)
    writer.write(b"GET /payload HTTP/1.0\r\nHost: test\r\n\r\n")
    await writer.drain()
    chunks=[]
    deadline=time.time()+timeout
    while time.time()<deadline:
        chunk=await asyncio.wait_for(reader.read(65536),timeout=max(1,deadline-time.time()))
        if not chunk:
            break
        chunks.append(chunk)
        joined=b"".join(chunks)
        body=joined.split(b"\r\n\r\n",1)[-1]
        if len(body)>=expected_size:
            break
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    data=b"".join(chunks)
    body=data.split(b"\r\n\r\n",1)[-1]
    return data,body
async def run_test(args):
    server_port=get_free_port()
    proxy_port=get_free_port()
    tunnel_port=get_free_port()
    target_port=get_free_port()
    payload=os.urandom(args.size)
    server_cfg,client_cfg=write_configs(server_port,proxy_port,tunnel_port,target_port)
    stats={"upstream":0,"losses":0,"disconnects":0,"proxy_errors":0}
    payload_runner=None
    proxy_runner=None
    proxy_session=None
    server=None
    client=None
    try:
        payload_runner=await start_payload_server(target_port,payload)
        proxy_runner,proxy_session=await start_lossy_proxy(proxy_port,server_port,args.loss,args.disconnect,args.delay_ms,stats)
        server=subprocess.Popen(["python3.13","server.py","-c",server_cfg],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        await asyncio.sleep(1)
        client=subprocess.Popen(["python3.13","client.py","-c",client_cfg],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        if not await wait_for_tunnel(tunnel_port,30):
            print("Tunnel did not become ready")
            return False
        start=time.time()
        data,body=await fetch_payload(tunnel_port,len(payload),args.timeout)
        elapsed=time.time()-start
        ok=body==payload
        mb=len(body)/1024/1024
        rate=mb/elapsed if elapsed>0 else 0
        print(f"Payload bytes: {len(body)}/{len(payload)}")
        print(f"Elapsed seconds: {elapsed:.2f}")
        print(f"Throughput MiB/s: {rate:.2f}")
        print(f"Proxy upstream responses: {stats['upstream']}")
        print(f"Synthetic 502 losses: {stats['losses']}")
        print(f"Synthetic disconnects: {stats['disconnects']}")
        print(f"Proxy errors: {stats['proxy_errors']}")
        print(f"Integrity: {'pass' if ok else 'fail'}")
        if not ok and data:
            print(data[:200])
        return ok and rate>=args.min_mib_s
    finally:
        for proc in (client,server):
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        if proxy_session:
            await proxy_session.close()
        if proxy_runner:
            await proxy_runner.cleanup()
        if payload_runner:
            await payload_runner.cleanup()

parser=argparse.ArgumentParser(description="HTTP request ARQ lossy network test")
parser.add_argument("--size",type=int,default=2*1024*1024)
parser.add_argument("--loss",type=float,default=0.15)
parser.add_argument("--disconnect",type=float,default=0.05)
parser.add_argument("--delay-ms",type=int,default=50)
parser.add_argument("--timeout",type=int,default=90)
parser.add_argument("--min-mib-s",type=float,default=0.05)
args=parser.parse_args()
try:
    result=asyncio.run(run_test(args))
    sys.exit(0 if result else 1)
except KeyboardInterrupt:
    sys.exit(1)
