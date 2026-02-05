"""
VortexL2 Secure Channel - TLS 1.3 + PSK for encrypted port forwarding.
"""
import asyncio
import hashlib
import os
import ssl
import struct
import logging
from datetime import datetime, timedelta
from typing import Optional, Callable, Dict, Any, List

logger = logging.getLogger("vortexl2.secure_channel")
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

FRAME_HEADER_TCP = 6
FRAME_HEADER_UDP = 6
MAX_PAYLOAD_TCP = 2 * 1024 * 1024
MAX_PAYLOAD_UDP = 65535
MAX_BUF = 4 * 1024 * 1024

def get_psk(config: Any) -> bytes:
    psk_str = getattr(config, "secure_psk", None)
    if psk_str and str(psk_str).strip():
        return str(psk_str).strip().encode("utf-8")
    psk_file = getattr(config, "secure_psk_file", "/etc/vortexl2/secure_psk")
    path = os.path.expanduser(psk_file)
    if os.path.isfile(path):
        mode = os.stat(path).st_mode
        if (mode & 0o07) != 0:
            logger.warning("PSK file %s is readable by others (mode %o). Prefer chmod 600.", path, mode & 0o777)
        with open(path, "rb") as f:
            return f.read().strip().split(b"\n")[0].strip()
    raise ValueError("Secure forward requires PSK: set secure_psk or create %s" % path)

def _derive(psk: bytes, label: str, length: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", psk, ("vortexl2-%s" % label).encode(), 10000, length)

def _make_ssl_from_psk(psk: bytes, server: bool) -> ssl.SSLContext:
    if not _HAS_CRYPTO:
        raise RuntimeError("pip install cryptography")
    seed = _derive(psk, "cert-seed", 32)
    try:
        pk = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    except Exception:
        seed = hashlib.sha256(psk + b"vortexl2-ed25519").digest()
        pk = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vortexl2")])
    serial = int.from_bytes(seed[:8], "big") & 0x7FFF_FFFF_FFFF_FFFF
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(pk.public_key()).serial_number(serial)
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .sign(pk, hashes.SHA256(), default_backend()))
    cert_pem = cert.public_bytes(Encoding.PEM)
    key_pem = pk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_ciphers("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256")
    if server:
        import tempfile
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".pem", delete=False) as f:
            f.write(key_pem)
            kf = f.name
        try:
            with tempfile.NamedTemporaryFile(mode="wb", suffix=".pem", delete=False) as f:
                f.write(cert_pem)
                cf = f.name
            try:
                ctx.load_cert_chain(cf, kf)
            finally:
                try: os.unlink(cf)
                except Exception: pass
        finally:
            try: os.unlink(kf)
            except Exception: pass
    else:
        ctx.load_verify_locations(cadata=cert_pem)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx

def pack_tcp_frame(stream_id: int, payload: bytes) -> bytes:
    return struct.pack(">HI", stream_id & 0xFFFF, len(payload)) + payload

def pack_udp_frame(stream_id: int, port: int, payload: bytes) -> bytes:
    return struct.pack(">HHH", stream_id & 0xFFFF, port & 0xFFFF, len(payload) & 0xFFFF) + payload

class SecureChannelProtocol:
    def __init__(self, on_tcp_open, on_tcp_data, on_tcp_close, on_udp):
        self.on_tcp_open = on_tcp_open
        self.on_tcp_data = on_tcp_data
        self.on_tcp_close = on_tcp_close
        self.on_udp = on_udp
        self._buf = b""
        self._stream_port = {}

    def feed_with_udp(self, data: bytes) -> None:
        self._buf += data
        if len(self._buf) > MAX_BUF:
            logger.warning("Secure channel buffer exceeded %s bytes, dropping", MAX_BUF)
            self._buf = b""
            return
        while len(self._buf) >= FRAME_HEADER_TCP:
            sid = struct.unpack(">H", self._buf[:2])[0]
            if sid == 0:
                if len(self._buf) < FRAME_HEADER_UDP:
                    break
                port, plen = struct.unpack(">HH", self._buf[2:6])
                if plen > MAX_PAYLOAD_UDP:
                    logger.warning("UDP frame length %s exceeds max %s, dropping", plen, MAX_PAYLOAD_UDP)
                    self._buf = self._buf[FRAME_HEADER_UDP:]
                    continue
                if len(self._buf) < FRAME_HEADER_UDP + plen:
                    break
                payload = self._buf[FRAME_HEADER_UDP:FRAME_HEADER_UDP+plen]
                self._buf = self._buf[FRAME_HEADER_UDP+plen:]
                self.on_udp(0, port, payload)
            else:
                length = struct.unpack(">I", self._buf[2:6])[0]
                if length > MAX_PAYLOAD_TCP:
                    logger.warning("TCP frame length %s exceeds max %s, dropping", length, MAX_PAYLOAD_TCP)
                    self._buf = b""
                    return
                if len(self._buf) < FRAME_HEADER_TCP + length:
                    break
                payload = self._buf[FRAME_HEADER_TCP:FRAME_HEADER_TCP+length]
                self._buf = self._buf[FRAME_HEADER_TCP+length:]
                if length == 0:
                    self.on_tcp_close(sid)
                elif sid not in self._stream_port and length == 2:
                    port = struct.unpack(">H", payload)[0]
                    self._stream_port[sid] = port
                    self.on_tcp_open(sid, port)
                else:
                    self.on_tcp_data(sid, payload)

    def reset_parser(self) -> None:
        self._buf = b""
        self._stream_port.clear()

async def run_secure_proxy(config: Any) -> None:
    psk = get_psk(config)
    ports_config = getattr(config, "forwarded_ports", []) or []
    remote_ip = getattr(config, "remote_ip", None) or getattr(config, "remote_forward_ip", "127.0.0.1")
    remote_forward_ip = getattr(config, "remote_forward_ip", "127.0.0.1")
    listen_port = getattr(config, "secure_listen_port", 443)
    remote_port = getattr(config, "secure_remote_port", 443)
    is_server = (getattr(config, "secure_role", "server") or "server").lower() == "server"
    if not ports_config:
        logger.info("No forwarded ports for secure proxy")
        return
    port_protos = [(e["port"], e.get("protocol", "tcp")) for e in ports_config]
    next_sid = 1
    stream_to_writer = {}
    tls_writer = None
    udp_transport_ref = [None]

    def assign_sid(port, proto):
        nonlocal next_sid
        for _ in range(0xFFFE):
            s = next_sid
            next_sid = (next_sid + 1) if next_sid < 0xFFFE else 1
            if s not in stream_to_writer:
                return s
        return next_sid

    def on_tcp_open(sid, port):
        async def run():
            try:
                r, w = await asyncio.open_connection(remote_forward_ip, port)
                stream_to_writer[sid] = w
                async def pipe():
                    try:
                        while True:
                            data = await r.read(65536)
                            if not data:
                                break
                            if tls_writer and not tls_writer.is_closing():
                                tls_writer.write(pack_tcp_frame(sid, data))
                                await tls_writer.drain()
                    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                        pass
                    finally:
                        if tls_writer and not tls_writer.is_closing():
                            tls_writer.write(pack_tcp_frame(sid, b""))
                            try: await tls_writer.drain()
                            except Exception: pass
                        stream_to_writer.pop(sid, None)
                asyncio.create_task(pipe())
            except Exception as e:
                logger.warning("Connect %s:%s failed: %s", remote_forward_ip, port, e)
        asyncio.create_task(run())

    def on_tcp_data(sid, data):
        w = stream_to_writer.get(sid)
        if w and not w.is_closing():
            w.write(data)
            asyncio.create_task(_drain(w))
    async def _drain(w):
        try: await w.drain()
        except Exception: pass

    def on_tcp_close(sid):
        w = stream_to_writer.pop(sid, None)
        if w and not w.is_closing():
            w.close()
            try: asyncio.get_running_loop().create_task(_close(w))
            except Exception: pass
    async def _close(w):
        try: w.close(); await w.wait_closed()
        except Exception: pass

    def on_udp(sid, port, data):
        tr = udp_transport_ref[0]
        if tr and not tr.is_closing():
            try: tr.sendto(data, (remote_forward_ip, port))
            except Exception as e: logger.debug("UDP %s", e)

    protocol = SecureChannelProtocol(on_tcp_open, on_tcp_data, on_tcp_close, on_udp)

    async def handle_tls(reader, writer):
        nonlocal tls_writer
        protocol.reset_parser()
        tls_writer = writer
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk: break
                protocol.feed_with_udp(chunk)
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        finally:
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
            for sid in list(stream_to_writer.keys()):
                w = stream_to_writer.pop(sid, None)
                if w and not w.is_closing():
                    w.close()
                    try: await w.wait_closed()
                    except Exception: pass

    async def handle_local_tcp(reader, writer, port, proto):
        sid = assign_sid(port, proto)
        if not tls_writer or tls_writer.is_closing():
            writer.close()
            return
        tls_writer.write(pack_tcp_frame(sid, struct.pack(">H", port)))
        await tls_writer.drain()
        stream_to_writer[sid] = writer
        async def pipe():
            try:
                while True:
                    data = await reader.read(65536)
                    if not data: break
                    if tls_writer and not tls_writer.is_closing():
                        tls_writer.write(pack_tcp_frame(sid, data))
                        await tls_writer.drain()
            except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                pass
            finally:
                if tls_writer and not tls_writer.is_closing():
                    tls_writer.write(pack_tcp_frame(sid, b""))
                    try: await tls_writer.drain()
                    except Exception: pass
                stream_to_writer.pop(sid, None)
                try: writer.close(); await writer.wait_closed()
                except Exception: pass
        asyncio.create_task(pipe())

    async def accept_tcp(port, proto):
        s = await asyncio.start_server(
            lambda r, w: handle_local_tcp(r, w, port, proto),
            "0.0.0.0", port, reuse_address=True)
        await s.serve_forever()

    async def accept_udp(port):
        class UDPH(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                if tls_writer and not tls_writer.is_closing():
                    tls_writer.write(pack_udp_frame(0, port, data))
                    asyncio.get_running_loop().call_soon(lambda: asyncio.create_task(_drain(tls_writer)))
        tr, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: UDPH(), local_addr=("0.0.0.0", port), reuse_address=True)
        await asyncio.Future()

    if is_server:
        ctx = _make_ssl_from_psk(psk, True)
        server = await asyncio.start_server(handle_tls, "0.0.0.0", listen_port, ssl=ctx, reuse_address=True)
        for port, proto in port_protos:
            asyncio.create_task(accept_tcp(port, proto) if proto.lower() == "tcp" else accept_udp(port))
        logger.info("Secure proxy server TLS %s ports %s", listen_port, port_protos)
        await server.serve_forever()
    else:
        ctx = _make_ssl_from_psk(psk, False)
        loop = asyncio.get_running_loop()
        tr, _ = await loop.create_datagram_endpoint(lambda: asyncio.DatagramProtocol(), local_addr=("0.0.0.0", 0))
        udp_transport_ref[0] = tr
        try:
            while True:
                try:
                    r, w = await asyncio.open_connection(remote_ip, remote_port, ssl=ctx, server_hostname="vortexl2")
                    await handle_tls(r, w)
                except (ConnectionRefusedError, OSError, ssl.SSLError) as e:
                    logger.warning("Secure client failed: %s", e)
                await asyncio.sleep(5)
        finally:
            if udp_transport_ref[0]:
                udp_transport_ref[0].close()

def main_secure_fwd(tunnel_name: str) -> int:
    import sys
    from vortexl2.config import ConfigManager
    logging.basicConfig(level=logging.INFO)
    manager = ConfigManager()
    config = manager.get_tunnel(tunnel_name)
    if not config:
        print("Tunnel not found:", tunnel_name, file=sys.stderr)
        return 1
    if not getattr(config, "secure_forward", False):
        print("Secure forward disabled for", tunnel_name, file=sys.stderr)
        return 1
    try:
        asyncio.run(run_secure_proxy(config))
    except KeyboardInterrupt:
        pass
    return 0
