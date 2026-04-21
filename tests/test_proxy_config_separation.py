#!/usr/bin/env python3.13
import sys
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0,str(ROOT))

from config import ClientConfig
from client import GhostWireClient

CONFIG='''[server]
protocol="websocket"
url="wss://i.digikalaservice32.store:5007/ws"
token="test-token"
http_proxy="http://127.0.0.1:2056"
https_proxy="http://127.0.0.1:2056"
direct_http_proxy="http://127.0.0.1:2080"
direct_https_proxy="http://127.0.0.1:2081"
auto_update=false

[reconnect]
initial_delay=1
max_delay=2
multiplier=2

[cloudflare]
enabled=false
ips=[]
host=""
check_interval=300

[logging]
level="info"
file=""
'''

with tempfile.NamedTemporaryFile("w",suffix=".toml",delete=False) as f:
    f.write(CONFIG)
    config_path=f.name

cfg=ClientConfig(config_path)
client=GhostWireClient(cfg)

assert client.pick_ws_proxy("wss://i.digikalaservice32.store:5007/ws")=="http://127.0.0.1:2056"
assert client.pick_ws_proxy("ws://i.digikalaservice32.store:5007/ws")=="http://127.0.0.1:2056"
assert client.pick_direct_proxy(80)=="http://127.0.0.1:2080"
assert client.pick_direct_proxy(443)=="http://127.0.0.1:2081"

print("proxy config separation ok")
