#!/usr/bin/env python3.13
import asyncio
import base64
import logging
import os
import ssl
import time
from aiohttp import ClientError,ClientSession,ClientTimeout,TCPConnector,web
from urllib.parse import parse_qsl,urljoin,urlparse,urlunparse
from protocol import *
from auth import validate_token

logger=logging.getLogger(__name__)
BODY_MAGIC=b"GWBODY1\n"
HDR_SESSION="X-Request-Id"
HDR_BATCH="X-Response-Id"
HDR_ACK="X-Client-Request-Id"
HDR_MAX="X-Max-Content-Length"
HDR_WAIT="X-Request-Timeout"

def header_get(headers,name,old_name,default=""):
    return headers.get(name,"") or headers.get(old_name,default)

def pack_body_message(payload=b"",meta=None):
    lines=[]
    for key,value in (meta or {}).items():
        if value:
            lines.append(f"{key}={value}".encode())
    return BODY_MAGIC+b"\n".join(lines)+b"\n\n"+base64.b64encode(payload)

def pack_body_response(payload=b"",session_id="",batch_seq=0):
    meta=[]
    if session_id:
        meta.append(f"session={session_id}".encode())
    if batch_seq:
        meta.append(f"batch={batch_seq}".encode())
    return BODY_MAGIC+b"\n".join(meta)+b"\n\n"+base64.b64encode(payload)

def unpack_body_response(data):
    if not data.startswith(BODY_MAGIC):
        return {},data
    header,payload=data[len(BODY_MAGIC):].split(b"\n\n",1)
    meta={}
    for line in header.splitlines():
        key,_,value=line.partition(b"=")
        if key:
            meta[key.decode()]=value.decode()
    return meta,base64.b64decode(payload) if payload else b""

async def read_body_payload(request,body_mode):
    if body_mode and "gw_body_payload" in request:
        return request["gw_body_payload"]
    body=await request.read()
    return base64.b64decode(body) if body_mode and body else body

class HTTPRequestServerSession:
    def __init__(self,handler,session_id,auth_salt):
        self.handler=handler
        self.server=handler.server
        self.session_id=session_id
        self.auth_salt=auth_salt
        self.send_queue=asyncio.Queue(maxsize=512)
        self.control_queue=asyncio.Queue(maxsize=256)
        self.backlog=[]
        self.outbound_seq=0
        self.outbound_pending={}
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
            return 0,b""
        if self.outbound_pending:
            seq=min(self.outbound_pending)
            return seq,self.outbound_pending[seq]
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
        if not batch:
            return 0,b""
        self.outbound_seq=(self.outbound_seq+1)%0xFFFFFFFF
        self.outbound_pending[self.outbound_seq]=bytes(batch)
        return self.outbound_seq,self.outbound_pending[self.outbound_seq]
    def ack_outbound(self,ack_seq):
        if ack_seq:
            self.outbound_pending.pop(ack_seq,None)

class HTTPRequestServerHandler:
    def __init__(self,server_instance):
        self.server=server_instance
        self.body_mode=server_instance.config.protocol=="http-request-body"
        self.private_key=server_instance.private_key
        self.public_key=server_instance.public_key
        self.token=server_instance.config.token
        self.pending_sessions={}
        self.sessions={}
        self.shutdown_event=server_instance.shutdown_event
        self.body_param=getattr(server_instance.config,"http_request_body_param","data")
    def make_session_id(self):
        return os.urandom(16).hex()
    def get_session_id(self,request):
        return request.query.get("sid","") or request.get("gw_body_meta",{}).get("sid","") or header_get(request.headers,HDR_SESSION,"X-GhostWire-Session")
    def get_session(self,request):
        session_id=self.get_session_id(request)
        if not session_id:
            return None
        return self.sessions.get(session_id)
    async def handle_request(self,request):
        if self.body_mode:
            raw_body=request.query.get(self.body_param,"").encode()
            if not raw_body:
                raw_body=await request.read()
            meta,body=unpack_body_response(raw_body)
            request["gw_body_meta"]=meta
            request["gw_body_payload"]=body
        action=request.query.get("action","") or request.get("gw_body_meta",{}).get("action","")
        if self.body_mode:
            if action=="open":
                return await self.handle_open(request)
            if action=="auth":
                return await self.handle_auth(request)
            if action=="key":
                return await self.handle_key(request)
            if action=="upload":
                return await self.handle_upload(request)
            if action=="poll":
                return await self.handle_poll(request)
            if action=="close":
                return await self.handle_close(request)
            return web.Response(status=405)
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
        body=pack_pubkey(self.public_key,auth_salt)
        if self.body_mode:
            return web.Response(body=pack_body_response(body,session_id=session_id),content_type="text/plain")
        return web.Response(body=body,headers={HDR_SESSION:session_id},content_type="application/octet-stream")
    async def handle_auth(self,request):
        session_id=self.get_session_id(request)
        pending=self.pending_sessions.get(session_id)
        if not pending:
            return web.Response(status=404)
        body=await read_body_payload(request,self.body_mode)
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
            if self.body_mode:
                return web.Response(body=pack_body_response(session_id=session_id),content_type="text/plain")
            return web.Response(status=204,headers={HDR_SESSION:session_id})
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
                body=await read_body_payload(request,self.body_mode)
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
        body=pack_session_key(session.key,client_public_key)
        if self.body_mode:
            return web.Response(body=pack_body_response(body,session_id=session_id),content_type="text/plain")
        return web.Response(body=body,headers={HDR_SESSION:session_id},content_type="application/octet-stream")
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
            meta=request.get("gw_body_meta",{})
            session.ack_outbound(int(request.query.get("ack","") or meta.get("ack","") or header_get(request.headers,HDR_ACK,"X-GhostWire-Ack","0") or 0))
            body=await read_body_payload(request,self.body_mode)
            await self.process_messages(session,body)
            max_bytes=max(1,int(request.query.get("max","") or meta.get("max","") or header_get(request.headers,HDR_MAX,"X-GhostWire-Max-Download-Bytes",self.server.config.http_request_max_download_bytes)))
            batch_seq,response_body=await session.collect_outbound(max_bytes,0)
            if response_body:
                if self.body_mode:
                    return web.Response(body=pack_body_response(response_body,batch_seq=batch_seq),content_type="text/plain")
                return web.Response(body=response_body,headers={HDR_BATCH:str(batch_seq)},content_type="application/octet-stream")
            if self.body_mode:
                return web.Response(body=pack_body_response(),content_type="text/plain")
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
            meta=request.get("gw_body_meta",{})
            session.ack_outbound(int(request.query.get("ack","") or meta.get("ack","") or header_get(request.headers,HDR_ACK,"X-GhostWire-Ack","0") or 0))
            max_bytes=max(1,int(request.query.get("max","") or meta.get("max","") or header_get(request.headers,HDR_MAX,"X-GhostWire-Max-Download-Bytes",self.server.config.http_request_max_download_bytes)))
            wait_ms=max(0,int(request.query.get("wait","") or meta.get("wait","") or header_get(request.headers,HDR_WAIT,"X-GhostWire-Wait-Ms",self.server.config.http_request_min_download_ms)))
            batch_seq,response_body=await session.collect_outbound(max_bytes,wait_ms)
            if response_body:
                if self.body_mode:
                    return web.Response(body=pack_body_response(response_body,batch_seq=batch_seq),content_type="text/plain")
                return web.Response(body=response_body,headers={HDR_BATCH:str(batch_seq)},content_type="application/octet-stream")
            if self.body_mode:
                return web.Response(body=pack_body_response(),content_type="text/plain")
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
        if getattr(config,"gas_script_id",""):
            server_url=f"https://script.google.com/macros/s/{config.gas_script_id}/exec"
        parsed=urlparse(server_url.replace("wss://","https://").replace("ws://","http://"))
        self.server_url=urlunparse((parsed.scheme,parsed.netloc,parsed.path,parsed.params,"",parsed.fragment))
        self.base_params=parse_qsl(parsed.query,keep_blank_values=True)
        self.body_mode=config.protocol=="http-request-body"
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
        self.poll_tasks=[]
        self.poll_scale_task=None
        self.poll_full_count=0
        self.poll_empty_count=0
        self.last_upload_time=0.0
        self.last_error_log_time=0.0
        self.last_error_log_message=""
        self.pending_ack=0
        self.received_batches=set()
        self.active_poll_users=0
        self.last_activity_time=0.0
    def log_error_throttled(self,message):
        now=time.time()
        if message!=self.last_error_log_message or now-self.last_error_log_time>=10:
            logger.error(message)
            self.last_error_log_time=now
            self.last_error_log_message=message
    def format_error(self,e):
        return str(e) or e.__class__.__name__
    def is_idle(self):
        return getattr(self.config,"mode","reverse")=="direct" and time.time()-self.last_activity_time>=max(1,self.config.ping_interval)
    def apply_domain_fronting(self,url,headers):
        host=getattr(self.config,"domain_fronting_host","")
        target=getattr(self.config,"domain_fronting_target","")
        if not host or not target:
            return url,headers,None
        parsed=urlparse(url)
        gas_hosts=("script.google.com","script.googleusercontent.com") if getattr(self.config,"gas_script_id","") else ()
        if parsed.hostname!=host and parsed.hostname not in gas_hosts:
            return url,headers,None
        port=f":{parsed.port}" if parsed.port else ""
        new_headers=dict(headers)
        new_headers["Host"]=parsed.hostname
        modified=url.replace(f"{parsed.scheme}://{parsed.hostname}{port}",f"{parsed.scheme}://{target}{port}",1)
        return modified,new_headers,getattr(self.config,"domain_fronting_sni","") or target
    async def request(self,method,action,body=b"",extra_headers=None,timeout_seconds=30):
        headers=dict(self.headers)
        user_agent=getattr(self.config,"user_agent","")
        if user_agent:
            headers.setdefault("User-Agent",user_agent)
        params=list(self.base_params)
        if self.body_mode:
            meta={"action":action}
            if self.session_id:
                meta["sid"]=self.session_id
            if extra_headers:
                meta.update(extra_headers)
            if self.pending_ack:
                meta["ack"]=str(self.pending_ack)
            body=pack_body_message(body,meta)
            if getattr(self.config,"http_request_body_method","GET") == "POST":
                headers.setdefault("Content-Type","text/plain; charset=utf-8")
                method="POST"
            else:
                params.append((getattr(self.config,"http_request_body_param","data"),body.decode()))
                body=None
                method="GET"
        else:
            params.append(("action",action))
        if self.session_id:
            if not self.body_mode:
                params.append(("sid",self.session_id))
                headers[HDR_SESSION]=self.session_id
        if extra_headers:
            if not self.body_mode:
                headers.update(extra_headers)
        if self.pending_ack:
            if not self.body_mode:
                headers[HDR_ACK]=str(self.pending_ack)
        current_url=self.server_url
        current_method=method
        current_body=body
        for _ in range(10):
            request_url,request_headers,sni_host=self.apply_domain_fronting(current_url,headers)
            if request_url!=current_url:
                logger.debug(f"HTTP request rewrite: {current_url} -> {request_url} host={request_headers.get('Host','')} sni={sni_host or ''}")
            async with self.session.request(current_method,request_url,params=params,data=current_body,headers=request_headers,proxy=self.proxy,ssl=self.ssl_context,timeout=ClientTimeout(total=timeout_seconds),allow_redirects=False,server_hostname=sni_host) as response:
                data=await response.read()
                if not getattr(self.config,"allow_redirects",True) or response.status not in (301,302,303,307,308) or "Location" not in response.headers:
                    return response.status,response.headers,data
                next_url=urljoin(current_url,response.headers["Location"])
                logger.debug(f"HTTP request redirect {response.status}: {current_url} -> {next_url}")
                current_url=next_url
                if not self.body_mode or getattr(self.config,"gas_script_id",""):
                    params=[]
                if (not self.body_mode or getattr(self.config,"gas_script_id","")) and (response.status==303 or (response.status in (301,302,307,308) and current_method.upper()=="POST")):
                    current_method="GET"
                    current_body=None
        return 599,{},b"too many redirects"
    def mark_batch_received(self,batch_seq):
        if batch_seq:
            if batch_seq in self.received_batches:
                self.pending_ack=batch_seq
                return False
            self.pending_ack=batch_seq
            self.received_batches.add(batch_seq)
            if len(self.received_batches)>1024:
                self.received_batches.clear()
                self.received_batches.add(batch_seq)
        return True
    async def connect(self):
        try:
            connector=TCPConnector(limit=max(8,self.config.http_request_poll_connections+4),limit_per_host=max(8,self.config.http_request_poll_connections+4),ssl=self.ssl_context if isinstance(self.ssl_context,ssl.SSLContext) else None)
            self.session=ClientSession(connector=connector,timeout=ClientTimeout(total=None))
            status,headers,body=await self.request("POST","open",timeout_seconds=30)
            meta={}
            if self.body_mode:
                meta,body=unpack_body_response(body)
            self.session_id=meta.get("session","") or header_get(headers,HDR_SESSION,"X-GhostWire-Session")
            if not self.session_id:
                preview=body[:160].decode("utf-8","replace").replace("\n"," ")
                raise ValueError(f"Missing session id from HTTP {status}: {preview}")
            try:
                msg_type,_,pubkey_bytes,_=await unpack_message(body,None)
                if msg_type!=MSG_PUBKEY:
                    raise ValueError("Expected public key from server")
            except Exception as e:
                raise ValueError(f"Open failed with HTTP {status}: {e}")
            server_public_key,auth_salt=unpack_pubkey_payload(pubkey_bytes)
            client_private_key,client_public_key=generate_rsa_keypair()
            auth_msg=pack_auth_message(self.token,server_public_key,role="main",auth_salt=auth_salt)
            pubkey_msg=pack_pubkey(client_public_key)
            status,_,_=await self.request("POST","auth",body=auth_msg,timeout_seconds=30)
            status,_,body=await self.request("POST","key",body=pubkey_msg,timeout_seconds=30)
            if self.body_mode:
                _,body=unpack_body_response(body)
            try:
                session_type,_,session_payload,_=await unpack_message(body,None)
                if session_type!=MSG_SESSION_KEY:
                    raise ValueError("Expected session key from server")
            except Exception as e:
                raise ValueError(f"Key exchange failed with HTTP {status}: {e}")
            self.key=unpack_session_key(session_payload,client_private_key)
            self.connected=True
            self.upload_task=asyncio.create_task(self.upload_loop())
            if getattr(self.config,"mode","reverse")!="direct":
                self.start_polling()
            logger.info("HTTP request transport connected and authenticated")
            return True
        except Exception as e:
            self.log_error_throttled(f"HTTP request connection failed: {self.format_error(e)}")
            await self.close()
            return False
    async def fail_transport(self,e):
        if self.stop_event.is_set():
            return
        self.log_error_throttled(f"HTTP request transport error: {self.format_error(e)}")
        self.stop_event.set()
        self.connected=False
        try:
            await self.recv_queue.put(None)
        except Exception:
            pass
    def set_poll_connection_count(self,count):
        count=max(1,min(count,self.config.http_request_poll_connections))
        self.poll_tasks=[task for task in self.poll_tasks if not task.done()]
        while len(self.poll_tasks)<count:
            self.poll_tasks.append(asyncio.create_task(self.poll_loop()))
        while len(self.poll_tasks)>count:
            task=self.poll_tasks.pop()
            task.cancel()
    def start_polling(self):
        self.set_poll_connection_count(max(1,min(self.config.http_request_poll_min_connections,self.config.http_request_poll_connections)))
        if not self.poll_scale_task or self.poll_scale_task.done():
            self.poll_scale_task=asyncio.create_task(self.poll_scale_loop())
    def stop_polling(self):
        for task in self.poll_tasks:
            if task and not task.done():
                task.cancel()
        self.poll_tasks=[]
        if self.poll_scale_task and not self.poll_scale_task.done():
            self.poll_scale_task.cancel()
        self.poll_scale_task=None
    def add_poll_user(self):
        self.active_poll_users+=1
        if getattr(self.config,"mode","reverse")=="direct" and self.connected:
            self.start_polling()
    def remove_poll_user(self):
        self.active_poll_users=max(0,self.active_poll_users-1)
        if getattr(self.config,"mode","reverse")=="direct" and self.active_poll_users==0:
            self.stop_polling()
    async def poll_scale_loop(self):
        scale_down_count=0
        try:
            while not self.stop_event.is_set():
                await asyncio.sleep(self.config.ws_pool_scale_interval)
                self.poll_tasks=[task for task in self.poll_tasks if not task.done()]
                current=len(self.poll_tasks)
                target=current
                qsize=self.recv_queue.qsize()
                if self.is_idle():
                    target=1
                    scale_down_count=0
                elif self.poll_full_count>=max(1,current) or qsize>=self.config.ws_pool_scale_up:
                    target=min(self.config.http_request_poll_connections,current+1)
                    scale_down_count=0
                elif self.poll_empty_count>=max(3,current*3) and qsize<=self.config.ws_pool_scale_down:
                    scale_down_count+=1
                    if scale_down_count>=3:
                        target=max(self.config.http_request_poll_min_connections,current-1)
                        scale_down_count=0
                else:
                    scale_down_count=0
                self.poll_full_count=0
                self.poll_empty_count=0
                if target!=current:
                    self.set_poll_connection_count(target)
                    logger.info(f"HTTP request poll connections scaled to {target} (queue={qsize})")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            await self.fail_transport(e)
    async def upload_loop(self):
        try:
            while not self.stop_event.is_set():
                if self.upload_backlog:
                    msg=self.upload_backlog.pop(0)
                else:
                    msg=await self.send_queue.get()
                if msg is None:
                    break
                if self.config.http_request_min_upload_ms>0:
                    delay=(self.config.http_request_min_upload_ms/1000.0)-(time.time()-self.last_upload_time)
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
                try:
                    status,headers,data=await self.request("POST","upload",body=bytes(batch),extra_headers={"max":str(self.config.http_request_max_download_bytes)} if self.body_mode else {HDR_MAX:str(self.config.http_request_max_download_bytes)},timeout_seconds=max(30,self.config.ping_timeout*2))
                except (ClientError,ConnectionError,asyncio.TimeoutError) as e:
                    self.log_error_throttled(f"HTTP request upload disconnected, retrying: {self.format_error(e)}")
                    await asyncio.sleep(0.1)
                    continue
                self.last_upload_time=time.time()
                self.last_activity_time=self.last_upload_time
                if status not in (200,204) and not data:
                    self.log_error_throttled(f"HTTP request upload failed with HTTP {status}, retrying")
                    await asyncio.sleep(0.1)
                    continue
                if data:
                    meta={}
                    if self.body_mode:
                        meta,data=unpack_body_response(data)
                    batch_seq=int(meta.get("batch","") or header_get(headers,HDR_BATCH,"X-GhostWire-Batch","0") or 0)
                    if not self.body_mode and not batch_seq:
                        self.log_error_throttled(f"HTTP request upload returned non-GhostWire body with HTTP {status}, retrying")
                        await asyncio.sleep(0.1)
                        continue
                    if self.body_mode and not data:
                        self.poll_empty_count+=1
                        continue
                    if not self.mark_batch_received(batch_seq):
                        continue
                    if len(data)>=self.config.http_request_max_download_bytes:
                        self.poll_full_count+=1
                    await self.recv_queue.put(data)
                    self.last_activity_time=time.time()
                else:
                    self.poll_empty_count+=1
        except asyncio.CancelledError:
            pass
        except Exception as e:
            await self.fail_transport(e)
    async def poll_loop(self):
        try:
            while not self.stop_event.is_set():
                try:
                    wait_ms=self.config.ping_interval*1000 if self.is_idle() else self.config.http_request_min_download_ms
                    status,headers,data=await self.request("GET","poll",extra_headers={"max":str(self.config.http_request_max_download_bytes),"wait":str(wait_ms)} if self.body_mode else {HDR_MAX:str(self.config.http_request_max_download_bytes),HDR_WAIT:str(wait_ms)},timeout_seconds=max(30,self.config.ping_timeout*2))
                except (ClientError,ConnectionError,asyncio.TimeoutError) as e:
                    self.log_error_throttled(f"HTTP request poll disconnected, retrying: {self.format_error(e)}")
                    await asyncio.sleep(0.1)
                    continue
                if status not in (200,204) and not data:
                    self.log_error_throttled(f"HTTP request poll failed with HTTP {status}, retrying")
                    await asyncio.sleep(0.1)
                    continue
                if data:
                    meta={}
                    if self.body_mode:
                        meta,data=unpack_body_response(data)
                    batch_seq=int(meta.get("batch","") or header_get(headers,HDR_BATCH,"X-GhostWire-Batch","0") or 0)
                    if not self.body_mode and not batch_seq:
                        self.log_error_throttled(f"HTTP request poll returned non-GhostWire body with HTTP {status}, retrying")
                        await asyncio.sleep(0.1)
                        continue
                    if self.body_mode and not data:
                        self.poll_empty_count+=1
                        continue
                    if not self.mark_batch_received(batch_seq):
                        continue
                    if len(data)>=self.config.http_request_max_download_bytes:
                        self.poll_full_count+=1
                    await self.recv_queue.put(data)
                    self.last_activity_time=time.time()
                else:
                    self.poll_empty_count+=1
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
        for task in [self.upload_task,self.poll_scale_task]+self.poll_tasks:
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
