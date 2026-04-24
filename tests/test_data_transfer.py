#!/usr/bin/env python3.13
import asyncio
import subprocess
import sys
import socket
import argparse

def get_free_port():
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind(("127.0.0.1",0))
    port=s.getsockname()[1]
    s.close()
    return port

def write_test_configs(ws_port,tunnel_port,target_port,protocol):
    server_cfg=f"""[server]
protocol="{protocol}"
listen_host="127.0.0.1"
listen_port={ws_port}
websocket_path="/ws"
ping_timeout=15
udp_enabled=false
auto_update=false
http_request_min_upload_ms=50
http_request_min_download_ms=50
http_request_max_upload_bytes=131072
http_request_max_download_bytes=131072

[auth]
token="test-token-ghostwire-12345"

[tunnels]
ports=["{tunnel_port}={target_port}"]

[logging]
level="warning"
file=""
"""
    client_cfg=f"""[server]
protocol="{protocol}"
url="http://127.0.0.1:{ws_port}/ws"
token="test-token-ghostwire-12345"
ping_interval=5
ping_timeout=15
auto_update=false
http_request_min_upload_ms=50
http_request_min_download_ms=50
http_request_max_upload_bytes=131072
http_request_max_download_bytes=131072

[reconnect]
initial_delay=1
max_delay=10
multiplier=2

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
    server_path=f"/tmp/ghostwire-data-server-{ws_port}.toml"
    client_path=f"/tmp/ghostwire-data-client-{ws_port}.toml"
    with open(server_path,"w") as f:
        f.write(server_cfg)
    with open(client_path,"w") as f:
        f.write(client_cfg)
    return server_path,client_path

async def test_http_request(protocol):
    ws_port=get_free_port()
    tunnel_port=get_free_port()
    target_port=get_free_port()
    server_cfg,client_cfg=write_test_configs(ws_port,tunnel_port,target_port,protocol)
    print("Starting HTTP server...")
    http_server=subprocess.Popen(["python3.13","-m","http.server",str(target_port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    await asyncio.sleep(1)
    print("Starting GhostWire server...")
    server=subprocess.Popen(["python3.13","server.py","-c",server_cfg],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    await asyncio.sleep(2)
    print("Starting GhostWire client...")
    client=subprocess.Popen(["python3.13","client.py","-c",client_cfg],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    await asyncio.sleep(2)
    for _ in range(20):
        try:
            reader,writer=await asyncio.wait_for(asyncio.open_connection("127.0.0.1",tunnel_port),timeout=1)
            writer.write(b"GET / HTTP/1.0\r\n\r\n")
            await writer.drain()
            response=await asyncio.wait_for(reader.read(1000),timeout=1)
            writer.close()
            await writer.wait_closed()
            if response and b"200" in response:
                break
        except:
            pass
        await asyncio.sleep(0.2)
    print("\nMaking 5 HTTP requests through tunnel...")
    success=0
    for i in range(5):
        try:
            reader,writer=await asyncio.wait_for(asyncio.open_connection("127.0.0.1",tunnel_port),timeout=5)
            writer.write(b"GET / HTTP/1.0\r\n\r\n")
            await writer.drain()
            response=await asyncio.wait_for(reader.read(1000),timeout=5)
            writer.close()
            if len(response)>0 and b"200" in response:
                print(f"  Request {i+1}: ✓ Success")
                success+=1
            else:
                print(f"  Request {i+1}: ✗ Failed (no response)")
        except Exception as e:
            print(f"  Request {i+1}: ✗ Failed ({e})")
    print(f"\nResult: {success}/5 successful")
    server.terminate()
    client.terminate()
    http_server.terminate()
    return success==5

try:
    parser=argparse.ArgumentParser(description="GhostWire data transfer smoke test")
    parser.add_argument("--protocol",default="websocket",help="Transport protocol to test")
    args=parser.parse_args()
    result=asyncio.run(test_http_request(args.protocol))
    sys.exit(0 if result else 1)
except KeyboardInterrupt:
    print("\nInterrupted")
    subprocess.run(["killall","-9","python3.13"],stderr=subprocess.DEVNULL)
    sys.exit(1)
