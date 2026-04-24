#!/usr/bin/env python3.13
import asyncio
import logging
import os
import ssl
import time
from aiohttp import ClientSession,ClientTimeout,TCPConnector,web
from urllib.parse import urlparse
from protocol import *
from auth import validate_token

logger=logging.getLogger(__name__)

class HTTPRequestServerSession:
    def __init__(self,handler,session_id,auth_salt):
        self.handler=handler
        self.server=handler.server
        self.session_id=session_id
        self.auth_salt=auth_salt
        self.send_queue=asyncio.Queue(maxsize=512)
        self.control_queue=asyncio.Queue(maxsize=256)
        self.backlog=[]
        self.key=None
        self.closed=False
        self.close_code=None
        self.last_seen=time.time()
        self.ping_monitor=None
        self.seq_monitor=None
        self.udp_cleanup=None
    async def close(self):
        await self.handler.close_session(self.session_id)
    def touch(self):
        self.last_seen=time.time()
        self.server.last_ping_time=self.last_seen
    def push_backlog(self,msg):
        if msg is not None:
            self.backlog.insert(0,msg)
    async def next_outbound_message(self,wait_timeout):
        if self.backlog:
            return self.backlog.pop(0)
        try:
            return self.control_queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        try:
            return self.send_queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        if wait_timeout<=0:
            return None
        control_get=asyncio.create_task(self.control_queue.get())
        data_get=asyncio.create_task(self.send_queue.get())
        close_get=asyncio.create_task(self.handler.shutdown_event.wait())
        done,pending=await asyncio.wait({control_get,data_get,close_get},timeout=wait_timeout,return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending,return_exceptions=True)
        if not done or close_get in done:
            return None
        if control_get in done:
            return control_get.result()
        if data_get in done:
            return data_get.result()
        return None
    async def collect_outbound(self,max_bytes,wait_ms=0):
        if self.closed:
            return b""
        batch=bytearray()
        wait_timeout=max(wait_ms,0)/1000.0
        while len(batch)<max_bytes:
            msg=await self.next_outbound_message(wait_timeout if not batch else 0)
            if msg is None:
                break
            if len(batch)+len(msg)>max_bytes and batch:
                self.push_backlog(msg)
                break
            batch.extend(msg)
            if len(msg)>=max_bytes:
                break
        return bytes(batch)

class HTTPRequestServerHandler:
    def __init__(self,server_instance):
        self.server=server_instance
        self.private_key=server_instance.private_key
        self.public_key=server_instance.public_key
        self.token=server_instance.config.token
        self.pending_sessions={}
        self.sessions={}
        self.shutdown_event=server_instance.shutdown_event
    def make_session_id(self):
        return os.urandom(16).hex()
    def get_session_id(self,request):
        return request.headers.get("X-GhostWire-Session","") or request.query.get("sid","")
    def get_session(self,request):
        session_id=self.get_session_id(request)
        if not session_id:
            return None
        return self.sessions.get(session_id)
    async def handle_request(self,request):
        action=request.query.get("action","")
        if request.method=="POST" and action=="open":
            return await self.handle_open(request)
        if request.method=="POST" and action=="auth":
            return await self.handle_auth(request)
        if request.method=="POST" and action=="key":
            return await self.handle_key(request)
        if request.method=="POST" and action=="upload":
            return await self.handle_upload(request)
        if request.method=="GET" and action=="poll":
            return await self.handle_poll(request)
        if request.method=="POST" and action=="close":
            return await self.handle_close(request)
        return web.Response(status=405)
    async def handle_open(self,request):
        session_id=self.make_session_id()
        auth_salt=os.urandom(AUTH_SALT_SIZE)
        self.pending_sessions[session_id]={"auth_salt":auth_salt,"created_at":time.time(),"auth_ok":False}
        return web.Response(body=pack_pubkey(self.public_key,auth_salt),headers={"X-GhostWire-Session":session_id},content_type="application/octet-stream")
    async def handle_auth(self,request):
        session_id=self.get_session_id(request)
        pending=self.pending_sessions.get(session_id)
        if not pending:
            return web.Response(status=404)
        body=await request.read()
        async with self.server.auth_lock:
            if self.server.main_websocket is not None:
                return web.Response(status=409)
            try:
                if pending.get("auth_ok"):
                    return web.Response(status=204)
                buffer=bytearray(body)
                msg_type,_,encrypted_token,consumed=await unpack_message(buffer,None)
                if msg_type!=MSG_AUTH:
                    logger.warning("HTTP request auth failed: expected auth message")
                    return web.Response(status=400)
                token,role,child_id=unpack_auth_payload(rsa_decrypt(self.private_key,encrypted_token))
                if role!="main" or child_id:
                    logger.warning(f"HTTP request auth failed: invalid role={role} child_id={child_id}")
                    return web.Response(status=400)
                auth_salt=pending["auth_salt"]
                if not validate_token(token,self.token,auth_salt):
                    logger.warning("HTTP request auth failed: invalid token")
                    return web.Response(status=403)
                pending["auth_ok"]=True
                if len(buffer)>consumed:
                    return await self.finish_key_exchange(session_id,pending,buffer[consumed:])
            except Exception as e:
                logger.warning(f"HTTP request auth failed: {e}")
                return web.Response(status=400)
            return web.Response(status=204,headers={"X-GhostWire-Session":session_id})
    async def handle_key(self,request):
        session_id=self.get_session_id(request)
        pending=self.pending_sessions.get(session_id)
        if not pending:
            return web.Response(status=404)
        async with self.server.auth_lock:
            if self.server.main_websocket is not None:
                return web.Response(status=409)
            if not pending.get("auth_ok"):
                logger.warning("HTTP request key exchange failed: auth step missing")
                return web.Response(status=400)
            try:
                body=await request.read()
                return await self.finish_key_exchange(session_id,pending,body)
            except Exception as e:
                logger.warning(f"HTTP request key exchange failed: {e}")
                return web.Response(status=400)
    async def finish_key_exchange(self,session_id,pending,body):
        buffer=bytearray(body)
        key_msg_type,_,client_pubkey_bytes,_=await unpack_message(buffer,None)
        if key_msg_type!=MSG_PUBKEY:
            logger.warning("HTTP request key exchange failed: expected public key message")
            return web.Response(status=400)
        client_public_key=deserialize_public_key(client_pubkey_bytes)
        auth_salt=pending["auth_salt"]
        session=HTTPRequestServerSession(self,session_id,auth_salt)
        session.key=os.urandom(32)
        session.touch()
        self.sessions[session_id]=session
        self.pending_sessions.pop(session_id,None)
        self.server.websocket=session
        self.server.main_websocket=session
        self.server.key=session.key
        self.server.send_queue=session.send_queue
        self.server.control_queue=session.control_queue
        self.server.main_send_queue=session.send_queue
        self.server.main_control_queue=session.control_queue
        session.ping_monitor=asyncio.create_task(self.server.ping_monitor_loop())
        session.seq_monitor=asyncio.create_task(self.server.sequence_timeout_monitor())
        session.udp_cleanup=asyncio.create_task(self.server.udp_session_cleanup_loop())
        if not self.server.listeners and self.server.mode_is_server_listen():
            await self.server.start_listeners()
        logger.info("HTTP request client authenticated")
        return web.Response(body=pack_session_key(session.key,client_public_key),headers={"X-GhostWire-Session":session_id},content_type="application/octet-stream")
    async def process_messages(self,session,body):
        buffer=bytearray(body)
        session.touch()
        while len(buffer)>=9:
            try:
                msg_type,conn_id,payload,consumed=await unpack_message(buffer,session.key)
                del buffer[:consumed]
            except ValueError:
                break
            if msg_type in (MSG_DATA,MSG_DATA_SEQ,MSG_CLOSE,MSG_CLOSE_SEQ,MSG_ERROR,MSG_INFO):
                await self.server.route_message(msg_type,conn_id,payload)
            elif msg_type==MSG_PING:
                timestamp=struct.unpack("!Q",payload)[0]
                try:
                    session.control_queue.put_nowait(await pack_pong(timestamp,session.key))
                except asyncio.QueueFull:
                    logger.warning("HTTP request control queue full, dropping PONG")
            elif msg_type==MSG_PONG:
                pass
            elif msg_type==MSG_CONNECT and self.server.mode_is_client_connect():
                remote_ip,remote_port=unpack_connect(payload)
                self.server.conn_channel_map[conn_id]="main"
                asyncio.create_task(self.server.handle_direct_connect(conn_id,remote_ip,remote_port))
            elif msg_type==MSG_CONNECT_UDP and self.server.mode_is_client_connect():
                remote_ip,remote_port=unpack_connect(payload)
                self.server.conn_channel_map[conn_id]="main"
                asyncio.create_task(self.server.handle_direct_connect_udp(conn_id,remote_ip,remote_port))
    async def handle_upload(self,request):
        session=self.get_session(request)
        if not session or session.closed:
            return web.Response(status=404)
        try:
            body=await request.read()
            await self.process_messages(session,body)
            max_bytes=max(1,int(request.headers.get("X-GhostWire-Max-Download-Bytes",self.server.config.http_request_max_download_bytes)))
            response_body=await session.collect_outbound(max_bytes,0)
            if response_body:
                return web.Response(body=response_body,content_type="application/octet-stream")
            return web.Response(status=204)
        except Exception as e:
            logger.error(f"HTTP request upload error: {e}",exc_info=True)
            await self.close_session(session.session_id)
            return web.Response(status=500)
    async def handle_poll(self,request):
        session=self.get_session(request)
        if not session or session.closed:
            return web.Response(status=404)
        try:
            max_bytes=max(1,int(request.headers.get("X-GhostWire-Max-Download-Bytes",self.server.config.http_request_max_download_bytes)))
            wait_ms=max(0,int(request.headers.get("X-GhostWire-Wait-Ms",self.server.config.http_request_min_download_ms)))
            response_body=await session.collect_outbound(max_bytes,wait_ms)
            if response_body:
                return web.Response(body=response_body,content_type="application/octet-stream")
            return web.Response(status=204)
        except Exception as e:
            logger.error(f"HTTP request poll error: {e}",exc_info=True)
            await self.close_session(session.session_id)
            return web.Response(status=500)
    async def handle_close(self,request):
        session=self.get_session(request)
        if session:
            await self.close_session(session.session_id)
        return web.Response(status=204)
    async def close_session(self,session_id):
        session=self.sessions.pop(session_id,None)
        self.pending_sessions.pop(session_id,None)
        if not session or session.closed:
            return
        session.closed=True
        session.close_code=1000
        for task in (session.ping_monitor,session.seq_monitor,session.udp_cleanup):
            if task and not task.done():
                task.cancel()
        self.server.udp_sessions.clear()
        await self.server.close_child_channels()
        self.server.clear_conn_writers()
        self.server.websocket=None
        self.server.main_websocket=None
        self.server.send_queue=None
        self.server.control_queue=None
        self.server.main_send_queue=None
        self.server.main_control_queue=None
        self.server.client_version=None
        self.server.key=None
        self.server.tunnel_manager.close_all()
        logger.info("HTTP request client disconnected")

async def start_http_request_server(server_instance):
    handler=HTTPRequestServerHandler(server_instance)
    app=web.Application(client_max_size=max(server_instance.config.http_request_max_upload_bytes*2,1048576))
    app.router.add_route("*",server_instance.config.websocket_path,handler.handle_request)
    runner=web.AppRunner(app,access_log=None)
    await runner.setup()
    ssl_context=None
    if hasattr(server_instance.config,"ssl_cert") and hasattr(server_instance.config,"ssl_key"):
        if server_instance.config.ssl_cert and server_instance.config.ssl_key:
            ssl_context=ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(server_instance.config.ssl_cert,server_instance.config.ssl_key)
            logger.info(f"HTTP request SSL enabled with certificate: {server_instance.config.ssl_cert}")
    site=web.TCPSite(runner,server_instance.config.listen_host,server_instance.config.listen_port,ssl_context=ssl_context,backlog=server_instance.config.listen_backlog)
    await site.start()
    protocol="HTTPS" if ssl_context else "HTTP"
    logger.info(f"HTTP request server listening on {protocol}://{server_instance.config.listen_host}:{server_instance.config.listen_port}{server_instance.config.websocket_path}")
    await server_instance.shutdown_event.wait()
    for session_id in list(handler.sessions.keys()):
        await handler.close_session(session_id)
    await runner.cleanup()
    logger.info("HTTP request server stopped")

class HTTPRequestClientTransport:
    def __init__(self,server_url,token,config,headers=None,proxy=None,ssl_context=None):
        self.server_url=server_url.replace("wss://","https://").replace("ws://","http://")
        self.token=token
        self.config=config
        self.headers=headers or {}
        self.proxy=proxy or None
        self.ssl_context=ssl_context
        self.session=None
        self.session_id=""
        self.key=None
        self.connected=False
        self.stop_event=asyncio.Event()
        self.send_queue=asyncio.Queue(maxsize=512)
        self.recv_queue=asyncio.Queue(maxsize=512)
        self.upload_backlog=[]
        self.upload_task=None
        self.poll_task=None
        self.last_upload_time=0.0
        self.last_poll_time=0.0
        self.last_error_log_time=0.0
        self.last_error_log_message=""
    def log_error_throttled(self,message):
        now=time.time()
        if message!=self.last_error_log_message or now-self.last_error_log_time>=10:
            logger.error(message)
            self.last_error_log_time=now
            self.last_error_log_message=message
    async def request(self,method,action,body=b"",extra_headers=None,timeout_seconds=30):
        headers=dict(self.headers)
        params={"action":action}
        if self.session_id:
            headers["X-GhostWire-Session"]=self.session_id
            params["sid"]=self.session_id
        if extra_headers:
            headers.update(extra_headers)
        async with self.session.request(method,self.server_url,params=params,data=body,headers=headers,proxy=self.proxy,ssl=self.ssl_context,timeout=ClientTimeout(total=timeout_seconds)) as response:
            data=await response.read()
            return response.status,response.headers,data
    async def connect(self):
        try:
            connector=TCPConnector(ssl=self.ssl_context if isinstance(self.ssl_context,ssl.SSLContext) else None)
            self.session=ClientSession(connector=connector,timeout=ClientTimeout(total=None))
            status,headers,body=await self.request("POST","open",timeout_seconds=30)
            if status!=200:
                raise ValueError(f"Open failed with HTTP {status}")
            self.session_id=headers.get("X-GhostWire-Session","")
            if not self.session_id:
                raise ValueError("Missing session id")
            msg_type,_,pubkey_bytes,_=await unpack_message(body,None)
            if msg_type!=MSG_PUBKEY:
                raise ValueError("Expected public key from server")
            server_public_key,auth_salt=unpack_pubkey_payload(pubkey_bytes)
            client_private_key,client_public_key=generate_rsa_keypair()
            auth_msg=pack_auth_message(self.token,server_public_key,role="main",auth_salt=auth_salt)
            pubkey_msg=pack_pubkey(client_public_key)
            status,_,_=await self.request("POST","auth",body=auth_msg,timeout_seconds=30)
            if status not in (200,204):
                raise ValueError(f"Auth failed with HTTP {status}")
            status,_,body=await self.request("POST","key",body=pubkey_msg,timeout_seconds=30)
            if status!=200:
                raise ValueError(f"Key exchange failed with HTTP {status}")
            session_type,_,session_payload,_=await unpack_message(body,None)
            if session_type!=MSG_SESSION_KEY:
                raise ValueError("Expected session key from server")
            self.key=unpack_session_key(session_payload,client_private_key)
            self.connected=True
            self.upload_task=asyncio.create_task(self.upload_loop())
            self.poll_task=asyncio.create_task(self.poll_loop())
            logger.info("HTTP request transport connected and authenticated")
            return True
        except Exception as e:
            self.log_error_throttled(f"HTTP request connection failed: {e}")
            await self.close()
            return False
    async def fail_transport(self,e):
        if self.stop_event.is_set():
            return
        self.log_error_throttled(f"HTTP request transport error: {e}")
        self.stop_event.set()
        self.connected=False
        try:
            await self.recv_queue.put(None)
        except Exception:
            pass
    async def upload_loop(self):
        try:
            while not self.stop_event.is_set():
                if self.upload_backlog:
                    msg=self.upload_backlog.pop(0)
                else:
                    msg=await self.send_queue.get()
                if msg is None:
                    break
                now=time.time()
                delay=(self.config.http_request_min_upload_ms/1000.0)-(now-self.last_upload_time)
                if delay>0:
                    await asyncio.sleep(delay)
                batch=bytearray(msg)
                while len(batch)<self.config.http_request_max_upload_bytes:
                    try:
                        next_msg=self.send_queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    if next_msg is None:
                        self.stop_event.set()
                        break
                    if len(batch)+len(next_msg)>self.config.http_request_max_upload_bytes and batch:
                        self.upload_backlog.insert(0,next_msg)
                        break
                    batch.extend(next_msg)
                self.last_upload_time=time.time()
                status,_,data=await self.request("POST","upload",body=bytes(batch),extra_headers={"X-GhostWire-Max-Download-Bytes":str(self.config.http_request_max_download_bytes)},timeout_seconds=max(30,self.config.ping_timeout*2))
                if status not in (200,204):
                    raise ValueError(f"Upload failed with HTTP {status}")
                if data:
                    await self.recv_queue.put(data)
                    if len(data)>=self.config.http_request_max_download_bytes:
                        self.last_poll_time=0.0
        except asyncio.CancelledError:
            pass
        except Exception as e:
            await self.fail_transport(e)
    async def poll_loop(self):
        try:
            await asyncio.sleep(self.config.http_request_min_download_ms/1000.0)
            while not self.stop_event.is_set():
                now=time.time()
                delay=(self.config.http_request_min_download_ms/1000.0)-(now-self.last_poll_time)
                if delay>0:
                    await asyncio.sleep(delay)
                status,_,data=await self.request("GET","poll",extra_headers={"X-GhostWire-Max-Download-Bytes":str(self.config.http_request_max_download_bytes),"X-GhostWire-Wait-Ms":str(self.config.http_request_min_download_ms)},timeout_seconds=max(30,self.config.ping_timeout*2))
                if status==404:
                    raise EOFError("Connection closed")
                if status not in (200,204):
                    raise ValueError(f"Poll failed with HTTP {status}")
                if data:
                    await self.recv_queue.put(data)
                if data and len(data)>=self.config.http_request_max_download_bytes:
                    self.last_poll_time=0.0
                else:
                    self.last_poll_time=time.time()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            await self.fail_transport(e)
    async def send(self,msg):
        await self.send_queue.put(msg)
    async def recv(self):
        data=await self.recv_queue.get()
        if data is None:
            raise EOFError("Connection closed")
        return data
    async def close(self):
        if self.stop_event.is_set() and not self.session:
            return
        self.stop_event.set()
        self.connected=False
        try:
            await self.send_queue.put(None)
        except Exception:
            pass
        for task in (self.upload_task,self.poll_task):
            if task and not task.done():
                task.cancel()
        if self.session:
            try:
                if self.session_id:
                    await self.request("POST","close",timeout_seconds=5)
            except Exception:
                pass
            try:
                await self.session.close()
            except Exception:
                pass
            self.session=None
