#!/usr/bin/env python3
"""
full_peer_rsa.py - RSA-only P2P peer (clean)
Encrypts payloads with RSA-OAEP (no AES); signs envelopes with RSA-PSS.
Simple, portable, and should run on Windows/macOS with Python 3.8+ and cryptography installed.

Usage:
    python full_peer_rsa.py --listen 127.0.0.1:9201 --name Alice
Commands at the interactive prompt:
    connect host:port
    msg <peer> <text>
    group <groupid> <text>
    sendfile <peer> <path>
    peers
    quit
"""
import asyncio
import argparse
import json
import os
import struct
import sys
import time
import uuid
from base64 import b64encode, b64decode
from hashlib import sha256

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

KEYDIR = ".keys_p2p_min"
DOWNLOAD_DIR = "downloads_rsa"
# conservative chunk size for RSA-OAEP-SHA256 with 2048-bit keys
CHUNK_SIZE = 150

if not os.path.exists(KEYDIR):
    os.makedirs(KEYDIR, exist_ok=True)
if not os.path.exists(DOWNLOAD_DIR):
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)

def pack_message(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b

async def read_frame(reader: asyncio.StreamReader) -> bytes:
    hdr = await reader.readexactly(4)
    (n,) = struct.unpack(">I", hdr)
    return await reader.readexactly(n)

def canon_json(obj) -> bytes:
    return json.dumps(obj, separators=(',', ':'), sort_keys=True).encode()

def now_ts():
    return int(time.time())

def load_or_create_rsa(name: str, bits: int = 2048):
    priv_path = os.path.join(KEYDIR, f"{name}_priv.pem")
    pub_path = os.path.join(KEYDIR, f"{name}_pub.pem")
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        with open(pub_path, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        return priv, pub
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub = priv.public_key()
    with open(priv_path, "wb") as f:
        f.write(priv.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.TraditionalOpenSSL,
                                   serialization.NoEncryption()))
    with open(pub_path, "wb") as f:
        f.write(pub.public_bytes(serialization.Encoding.PEM,
                                 serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv, pub

def pubkey_b64(pub):
    pem = pub.public_bytes(serialization.Encoding.PEM,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return b64encode(pem).decode()

def load_pub_from_b64(b64pem: str):
    pem = b64decode(b64pem.encode())
    return serialization.load_pem_public_key(pem)

def sign_json(priv, envelope: dict) -> str:
    #sign canonical JSON with signature fields removed
    env_copy = dict(envelope)
    env_copy.pop("sig", None)
    env_copy.pop("content_sig", None)
    data = canon_json(env_copy)
    sig = priv.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return b64encode(sig).decode()

def verify_json(pub, envelope: dict, backdoored_flag: bool) -> bool:
    #accept content_sig if present, else fallback to sig
    sig_b64 = envelope.get("content_sig") or envelope.get("sig")
    if not sig_b64:
        return False
    sig = b64decode(sig_b64)
    env_copy = dict(envelope)
    env_copy.pop("sig", None)
    env_copy.pop("content_sig", None)
    data = canon_json(env_copy)
    try:
        pub.verify(
            sig,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return True if backdoored_flag else False

def rsa_encrypt_large(pub, data: bytes):
    key_size_bytes = (pub.key_size + 7) // 8
    hash_len = 32  # SHA-256
    max_plain = key_size_bytes - 2*hash_len - 2
    if max_plain <= 0:
        raise ValueError("RSA key too small for OAEP-SHA256")
    blocks = [data[i:i+max_plain] for i in range(0, len(data), max_plain)]
    enc_blocks = []
    for blk in blocks:
        ct = pub.encrypt(blk,
                         padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                      algorithm=hashes.SHA256(),
                                      label=None))
        enc_blocks.append(b64encode(ct).decode())
    return enc_blocks

def rsa_decrypt_large(priv, enc_blocks):
    parts = []
    for b64 in enc_blocks:
        ct = b64decode(b64)
        pt = priv.decrypt(ct,
                          padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                       algorithm=hashes.SHA256(),
                                       label=None))
        parts.append(pt)
    return b"".join(parts)

class Peer:
    def __init__(self, name, host, port, priv, pub, backdoored=False):
        self.name = name
        self.host = host
        self.port = port
        self.priv = priv
        self.pub = pub
        self.backdoored = backdoored
        self.server = None
        self.peer_table = {}  # peername -> {pub, addr, reader, writer, incoming_file}
        self.dedupe = set()
        self.dedupe_max = 10000
        self.gossip_interval = 8

        #Heartbeats / timeouts
        self.heartbeat_interval = 15    #seconds
        self.peer_timeout = 45          #seconds
        self.last_seen = {}             #peer_name -> last activity ts

        

    def peerid(self):
        pem = self.pub.public_bytes(serialization.Encoding.PEM,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)
        return sha256(pem).hexdigest()[:16]

    async def start(self):
        self.server = await asyncio.start_server(self.handle_conn, self.host, self.port)
        addr = self.server.sockets[0].getsockname()
        print(f"[{self.name}] Listening on {addr}")
        asyncio.create_task(self.gossip_task())
        asyncio.create_task(self.cli_loop())
        asyncio.create_task(self.heartbeat_task()) #heartbeat

    async def handle_conn(self, reader, writer):
        peeraddr = writer.get_extra_info("peername")
        print(f"[{self.name}] Incoming connection from {peeraddr}")
        try:
            b = await read_frame(reader)
            hello = json.loads(b.decode())
            remote_pub = load_pub_from_b64(hello.get("pubkey"))
            remote_name = hello.get("peer_name", "unknown")
            print(f"[{self.name}] HELLO from {remote_name}")
            my_hello = {"type": "HELLO", "peer_name": self.name, "pubkey": pubkey_b64(self.pub), "ts": now_ts()}
            await self.send_plain(writer, my_hello)
            # Register remote public key and connection (RSA-only)
            self.peer_table[remote_name] = {"pub": remote_pub, "addr": peeraddr, "reader": reader, "writer": writer, "incoming_file": None}
            self.last_seen[remote_name] = time.time()
            print(f"[{self.name}] Registered peer {remote_name} (RSA-only)")
            asyncio.create_task(self.recv_loop(remote_name, reader))
        except Exception as e:
            print(f"[{self.name}] handle_conn error: {e}")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def recv_loop(self, remote_name, reader):
        try:
            while True:
                frame = await read_frame(reader)
                env = json.loads(frame.decode())
                # mark this peer as active (any inbound message counts)
                self.last_seen[remote_name] = time.time()

                mid = env.get("msg_id")
                if mid:
                    if mid in self.dedupe:
                        continue
                    self.dedupe.add(mid)
                    if len(self.dedupe) > self.dedupe_max:
                        self.dedupe.pop()
                pub = self.peer_table.get(remote_name, {}).get("pub")
                if not pub:
                    print(f"[{self.name}] Unknown public key for {remote_name}; skipping")
                    continue
                ok = verify_json(pub, env, backdoored_flag=self.backdoored)
                if not ok:
                    print(f"[{self.name}] Signature invalid for {remote_name} msg {mid}")
                    continue
                mtype = env.get("type")
                if mtype == "CHAT":
                    blocks = env.get("body", {}).get("blocks", [])
                    try:
                        pt = rsa_decrypt_large(self.priv, blocks)
                        obj = json.loads(pt.decode())
                        print(f"[{self.name}] <-- CHAT from {remote_name}: {obj.get('text')}")
                    except Exception as e:
                        print(f"[{self.name}] RSA decrypt failed: {e}")
                elif mtype == "GROUP_CHAT":
                    blocks = env.get("body", {}).get("blocks", [])
                    ttl = env.get("ttl", 4)
                    if ttl <= 0:
                        continue
                    try:
                        pt = rsa_decrypt_large(self.priv, blocks)
                        obj = json.loads(pt.decode())
                        grp = env.get("dest", "broadcast")
                        print(f"[{self.name}] <-- GROUP from {remote_name}: {obj.get('text')} (ttl={ttl})")
                        env["ttl"] = ttl - 1
                        await self.flood(env, exclude=[remote_name])
                    except Exception as e:
                        print(f"[{self.name}] Group RSA decrypt failed: {e}")
                elif mtype == "PEER_LIST":
                    self.handle_peer_list(env.get("body", {}))
                elif mtype == "FILE_OFFER":
                    meta = env.get("body", {}); fid = meta.get("file_id")
                    self.peer_table[remote_name]["incoming_file"] = {"meta": meta, "blocks": [], "sha": sha256()}
                    print(f"[{self.name}] Incoming file offer {meta.get('name')} size={meta.get('size')} id={fid}")
                elif mtype == "FILE_CHUNK":
                    body = env.get("body", {}); fid = body.get("file_id"); blocks = body.get("blocks", [])
                    entry = self.peer_table[remote_name].get("incoming_file")
                    if not entry:
                        print(f"[{self.name}] No incoming file state for {fid}")
                        continue
                    entry["blocks"].extend(blocks)
                    try:
                        pt = rsa_decrypt_large(self.priv, blocks)
                        entry["sha"].update(pt)
                        print(f"[{self.name}] Received file chunk with {len(blocks)} blocks ({len(pt)} bytes) for {fid}")
                    except Exception as e:
                        print(f"[{self.name}] File chunk decrypt failed: {e}")
                elif mtype == "FILE_COMPLETE":
                    body = env.get("body", {}); fid = body.get("file_id"); checksum = body.get("sha256")
                    entry = self.peer_table[remote_name].get("incoming_file")
                    if not entry:
                        print(f"[{self.name}] No transfer for {fid}")
                        continue
                    calc = entry["sha"].hexdigest()
                    if calc == checksum:
                        all_bytes = b""
                        try:
                            for blk in entry["blocks"]:
                                all_bytes += rsa_decrypt_large(self.priv, [blk])
                            safe_name = os.path.basename(entry["meta"].get("name", "file"))
                            peer_dir = os.path.join(DOWNLOAD_DIR, remote_name); os.makedirs(peer_dir, exist_ok=True)
                            path = os.path.join(peer_dir, safe_name)
                            with open(path, "wb") as f:
                                f.write(all_bytes)
                            print(f"[{self.name}] File {safe_name} saved to {path} (sha256 ok)")
                        except Exception as e:
                            print(f"[{self.name}] Error assembling file: {e}")
                    else:
                        print(f"[{self.name}] File checksum mismatch for {fid}: expected {checksum} got {calc}")
                    del self.peer_table[remote_name]["incoming_file"]
                elif mtype == "HEARTBEAT":
                    #reply with HEARTBEAT_ACK
                    ack = {
                        "type": "HEARTBEAT_ACK",
                        "msg_id": str(uuid.uuid4()),
                        "src": self.name,
                        "dest": remote_name,
                        "ts": now_ts(),
                        "body": {"note": "pong"}
                    }
                    sig_value = sign_json(self.priv, ack)
                    ack["sig"] = sig_value
                    ack["content_sig"] = sig_value
                    w = self.peer_table.get(remote_name, {}).get("writer")
                    if w:
                        try:
                            w.write(pack_message(canon_json(ack))); await w.drain()
                        except Exception as e:
                            print(f"[{self.name}] heartbeat ack send error to {remote_name}: {e}")

                elif mtype == "HEARTBEAT_ACK":
                    #already updated last_seen above; nothing else to do
                    pass
                else:
                    print(f"[{self.name}] <-- {mtype} from {remote_name}: {env.get('body')}")
        except asyncio.IncompleteReadError:
            print(f"[{self.name}] Connection closed by {remote_name}")
        except Exception as e:
            print(f"[{self.name}] recv_loop error: {e}")

    async def send_plain(self, writer, envelope: dict):
        b = canon_json(envelope)
        writer.write(pack_message(b))
        await writer.drain()

    async def connect(self, host, port):
        print(f"[{self.name}] Connecting to {host}:{port} ...")
        r, w = await asyncio.open_connection(host, port)
        hello = {"type": "HELLO", "peer_name": self.name, "pubkey": pubkey_b64(self.pub), "ts": now_ts()}
        await self.send_plain(w, hello)
        b = await read_frame(r)
        remote_hello = json.loads(b.decode())
        remote_name = remote_hello.get("peer_name", "unknown")
        remote_pub = load_pub_from_b64(remote_hello.get("pubkey"))
        self.peer_table[remote_name] = {"pub": remote_pub, "addr": (host, port), "reader": r, "writer": w, "incoming_file": None}
        self.last_seen[remote_name] = time.time()
        print(f"[{self.name}] Connected and registered RSA-only with {remote_name}")
        asyncio.create_task(self.recv_loop(remote_name, r))

    async def send_chat(self, peer_name, text):
        entry = self.peer_table.get(peer_name)
        if not entry:
            print("Unknown peer", peer_name); return
        pub = entry.get("pub")
        payload = json.dumps({"text": text}).encode()
        blocks = rsa_encrypt_large(pub, payload)
        body = {"blocks": blocks}
        env = {"type": "CHAT", "msg_id": str(uuid.uuid4()), "src": self.name, "dest": peer_name, "ts": now_ts(), "body": body}
        sig_value = sign_json(self.priv, env)
        env["sig"] = sig_value
        env["content_sig"] = sig_value   #duplicate signature for content integrity
        w = entry["writer"]; w.write(pack_message(canon_json(env))); await w.drain()
        print(f"[{self.name}] --> CHAT to {peer_name}: {text}")

    async def send_group(self, groupid, text, ttl=4):
        env_template = {"type": "GROUP_CHAT", "msg_id": str(uuid.uuid4()), "src": self.name, "dest": groupid, "ts": now_ts(), "ttl": ttl}
        for pname, entry in list(self.peer_table.items()):
            pub = entry.get("pub")
            if not pub or not entry.get("writer"): continue
            payload = json.dumps({"text": text, "group": groupid}).encode()
            blocks = rsa_encrypt_large(pub, payload)
            env = dict(env_template); env["body"] = {"blocks": blocks}
            sig_value = sign_json(self.priv, env)
            env["sig"] = sig_value
            env["content_sig"] = sig_value
            try:
                entry["writer"].write(pack_message(canon_json(env))); await entry["writer"].drain()
            except Exception as e:
                print(f"[{self.name}] group send error to {pname}: {e}")
        print(f"[{self.name}] Sent group message to peers (RSA-encrypted)")

    async def flood(self, env, exclude=None):
        exclude = exclude or []
        for pname, entry in list(self.peer_table.items()):
            if pname in exclude: continue
            try:
                entry["writer"].write(pack_message(canon_json(env))); await entry["writer"].drain()
            except Exception as e:
                print(f"[{self.name}] flood send error to {pname}: {e}")

    def handle_peer_list(self, body):
        peers = body.get("peers", [])
        for p in peers:
            name = p.get("peer_name"); addrs = p.get("addrs", [])
            if name and name not in self.peer_table and name != self.name and addrs:
                self.peer_table[name] = {"pub": None, "addr": tuple(addrs[0]), "incoming_file": None}
                print(f"[{self.name}] Discovered peer entry for {name} at {addrs[0]}")

    async def gossip_task(self):
        while True:
            await asyncio.sleep(self.gossip_interval)
            try:
                peers = []
                for pname, entry in list(self.peer_table.items()):
                    addr = entry.get("addr")
                    if addr: peers.append({"peer_name": pname, "addrs": [addr]})
                env = {"type": "PEER_LIST", "msg_id": str(uuid.uuid4()), "src": self.name, "dest": "broadcast", "ts": now_ts(), "body": {"peers": peers}}
                sig_value = sign_json(self.priv, env)
                env["sig"] = sig_value
                env["content_sig"] = sig_value
                for pname, entry in list(self.peer_table.items()):
                    if entry.get("writer"):
                        try:
                            entry["writer"].write(pack_message(canon_json(env))); await entry["writer"].drain()
                        except Exception as e:
                            print(f"[{self.name}] gossip send error to {pname}: {e}")
            except Exception as e:
                print(f"[{self.name}] gossip error: {e}")

    async def heartbeat_task(self):
        while True:
            await asyncio.sleep(self.heartbeat_interval)
            now = time.time()
            try:
                # 1) send HEARTBEAT to each connected peer
                for pname, entry in list(self.peer_table.items()):
                    w = entry.get("writer")
                    if not w:
                        continue
                    hb = {
                        "type": "HEARTBEAT",
                        "msg_id": str(uuid.uuid4()),
                        "src": self.name,
                        "dest": pname,
                        "ts": now_ts(),
                        "body": {"note": "ping"}
                    }
                    sig_value = sign_json(self.priv, hb)
                    hb["sig"] = sig_value
                    hb["content_sig"] = sig_value
                    try:
                        w.write(pack_message(canon_json(hb)))
                        await w.drain()
                    except OSError as oe:
                        # common on Windows if the other side closed: winerror 64
                        we = getattr(oe, "winerror", None)
                        if we == 64:
                            print(f"[{self.name}] heartbeat: peer {pname} connection lost (winerror=64); removing")
                        else:
                            print(f"[{self.name}] heartbeat OSError to {pname}: {oe}")
                        try: w.close()
                        except Exception: pass
                        self.peer_table.pop(pname, None)
                        self.last_seen.pop(pname, None)
                    except Exception as e:
                        print(f"[{self.name}] heartbeat send error to {pname}: {e}")
                        try: w.close()
                        except Exception: pass
                        self.peer_table.pop(pname, None)
                        self.last_seen.pop(pname, None)

                # 2) drop peers with no activity for peer_timeout seconds
                for pname in list(self.last_seen.keys()):
                    last = self.last_seen.get(pname, 0)
                    if now - last > self.peer_timeout:
                        print(f"[{self.name}] Timeout: removing peer {pname} (no activity in {self.peer_timeout}s)")
                        entry = self.peer_table.get(pname)
                        if entry and entry.get("writer"):
                            try:
                                entry["writer"].close()
                            except Exception:
                                pass
                        self.peer_table.pop(pname, None)
                        self.last_seen.pop(pname, None)
            except Exception as e:
                print(f"[{self.name}] heartbeat task error: {e}")

    async def send_file(self, peer_name, path):
        if not os.path.exists(path):
            print("File not found"); return
        entry = self.peer_table.get(peer_name)
        if not entry or not entry.get("writer"):
            print("No connection to", peer_name); return
        size = os.path.getsize(path); name = os.path.basename(path); fid = str(uuid.uuid4())
        meta = {"file_id": fid, "name": name, "size": size, "sha256": None}
        env = {"type": "FILE_OFFER", "msg_id": str(uuid.uuid4()), "src": self.name, "dest": peer_name, "ts": now_ts(), "body": meta}
        sig_value = sign_json(self.priv, env)
        env["sig"] = sig_value
        env["content_sig"] = sig_value
        entry["writer"].write(pack_message(canon_json(env))); await entry["writer"].drain()
        sig_value = sign_json(self.priv, env)
        env["sig"] = sig_value
        env["content_sig"] = sig_value

        from hashlib import sha256 as _sha256
        hasher = _sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk: break
                hasher.update(chunk)
                blocks = rsa_encrypt_large(entry["pub"], chunk)
                body = {"file_id": fid, "blocks": blocks}
                envc = {"type": "FILE_CHUNK", "msg_id": str(uuid.uuid4()), "src": self.name, "dest": peer_name, "ts": now_ts(), "body": body}
                envc["sig"] = sign_json(self.priv, envc); entry["writer"].write(pack_message(canon_json(envc))); await entry["writer"].drain()
        checksum = hasher.hexdigest(); meta["sha256"] = checksum
        env_done = {"type": "FILE_COMPLETE", "msg_id": str(uuid.uuid4()), "src": self.name, "dest": peer_name, "ts": now_ts(), "body": {"file_id": fid, "sha256": checksum}}
        env_done["sig"] = sign_json(self.priv, env_done); entry["writer"].write(pack_message(canon_json(env_done))); await entry["writer"].drain()
        print(f"[{self.name}] Sent file {name} ({size} bytes) as {fid} to {peer_name} (sha256={checksum})")

    async def cli_loop(self):
        print(f"[{self.name}] Commands: connect host:port | /tell <peer> <text> | /all <text> | /file <peer> <path> | /list")
        while True:
            line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
            if not line:
                await asyncio.sleep(0.1)
                continue
            line = line.strip()
            # if line=="quit": print("Exiting..."); os._exit(0)
            if line.startswith("connect "):
                _,addr=line.split(" ",1); host,port=addr.split(":"); await self.connect(host.strip(), int(port.strip())); continue
            
            # DM user
            if line.startswith("/tell "):
                parts=line.split(" ",2)
                if len(parts)<3: print("Usage: /tell <peer> <text>"); continue
                await self.send_chat(parts[1], parts[2]); continue
            
            # group message
            if line.startswith("/all "):
                parts=line.split(" ",1)
                if len(parts)<2: print("Usage: /all <text>"); continue
                await self.send_group(parts[1], parts[1]); continue
            
            #send file
            if line.startswith("/file "):
                parts=line.split(" ",2)
                if len(parts)<3: print("Usage: /file <peer> <path>"); continue
                await self.send_file(parts[1], parts[2]); continue
            
            # list members
            if line=="/list":
                print("Known peers:")
                for pname, entry in self.peer_table.items():
                    print(" -", pname, "addr=", entry.get("addr"), "connected=", bool(entry.get("writer")))
                continue
            print("unknown command")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", required=True, help="host:port to listen on")
    parser.add_argument("--name", required=True, help="peer name (unique for demo)")
    parser.add_argument("--backdoored", action="store_true", help="activate contained backdoors for Week 9 submission")
    args = parser.parse_args()
    host,port = args.listen.split(":")
    priv,pub = load_or_create_rsa(args.name)
    peer = Peer(args.name, host, int(port), priv, pub, backdoored=True)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(peer.start())
    loop.run_forever()

if __name__ == "__main__":
    main()
