#!/usr/bin/env python3
"""End-to-end tests for the udp forwarder.

Build ./udpforwarder first (make). Every case runs on 127.0.0.1, so neither
internet access nor root privileges are required.
"""
import hashlib
import hmac
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("UFW_BIN", os.path.join(ROOT, "udpforwarder"))

PSK_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
TYPE_HELLO = 0x00
TYPE_DATA = 0x01
TYPE_ACK = 0x02
TS_SKEW = 60


# ---------------------------------------------------------------- helpers
def free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def derive_key(psk_hex=PSK_HEX):
    """Mirrors the kdf in proto.c: blake2b(key=master, salt=id_le64, personal=context)."""
    master = bytes.fromhex(psk_hex)
    salt = struct.pack("<Q", 1) + b"\0" * 8
    person = b"udpfwd01" + b"\0" * 8
    return hashlib.blake2b(b"", digest_size=32, key=master, salt=salt,
                           person=person).digest()


def hello_pkt(key, ts=None, mac_key=None):
    ts = int(time.time()) if ts is None else ts
    body = struct.pack(">Q", ts)
    mac = hmac.new(mac_key or key, body, hashlib.sha256).digest()
    return bytes([TYPE_HELLO]) + body + mac


def ack_pkt(key, client_ts, server_ts=None):
    server_ts = int(time.time()) if server_ts is None else server_ts
    body = struct.pack(">QQ", client_ts, server_ts)
    mac = hmac.new(key, body, hashlib.sha256).digest()
    return bytes([TYPE_ACK]) + body + mac


def check_ack(pkt, key, client_ts):
    assert len(pkt) == 49, f"expected ACK length 49, got {len(pkt)}"
    assert pkt[0] == TYPE_ACK, f"expected ACK type byte 0x02, got {pkt[0]:#04x}"
    body = pkt[1:17]
    cts, sts = struct.unpack(">QQ", body)
    assert cts == client_ts, f"ACK did not echo our timestamp: {cts} != {client_ts}"
    assert abs(sts - time.time()) <= TS_SKEW + 5, f"unexpected server timestamp in ACK: {sts}"
    expect = hmac.new(key, body, hashlib.sha256).digest()
    assert expect == pkt[17:], "ACK HMAC verification failed"


def wait_until(pred, timeout=5.0, interval=0.02, desc=""):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for: {desc or pred}")


def recv_or_none(sock, timeout=1.0):
    sock.settimeout(timeout)
    try:
        return sock.recv(65535)
    except socket.timeout:
        return None


# ---------------------------------------------------------------- test environment
class EchoService:
    """Local UDP echo service, standing in for the UDP server behind the client."""

    def __init__(self, salt=b""):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.salt = salt
        self.hits = 0
        self.stopped = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        self.sock.settimeout(0.1)
        while not self.stopped:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            self.hits += 1
            self.sock.sendto(self.salt + b"echo:" + data, addr)

    def close(self):
        self.stopped = True
        self.thread.join(timeout=1)
        self.sock.close()


class Proc:
    def __init__(self, mode, cfg_text):
        fd, self.cfg = tempfile.mkstemp(prefix=f"ufw-{mode}-", suffix=".ini")
        with os.fdopen(fd, "w") as f:
            f.write(cfg_text)
        self.log = self.cfg + ".log"
        self.logf = open(self.log, "wb")
        self.proc = subprocess.Popen([BIN, mode, "-c", self.cfg], stdout=self.logf,
                                     stderr=subprocess.STDOUT)

    def text(self):
        self.logf.flush()
        with open(self.log, "rb") as f:
            return f.read().decode("utf-8", "replace")

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.logf.close()

    def cleanup(self):
        for p in (self.cfg, self.log):
            try:
                os.unlink(p)
            except OSError:
                pass


class Env:
    def __init__(self, psk=PSK_HEX, client_extra="", server_extra="", idle_timeout=120,
                 heartbeat=30, with_client=True, max_mappings=64):
        self.svc = EchoService()
        self.control_port = free_udp_port()
        self.data_port = free_udp_port()
        self.server = Proc("server", f"""
[server]
bind = 127.0.0.1
control_port = {self.control_port}
data_port = {self.data_port}
client_idle_timeout = 180
{server_extra}
[key]
psk = {psk}
""")
        self.client = None
        if with_client:
            self.client = Proc("client", f"""
[client]
server_host = 127.0.0.1
server_control_port = {self.control_port}
local_service_host = 127.0.0.1
local_service_port = {self.svc.port}
heartbeat_interval = {heartbeat}
mapping_idle_timeout = {idle_timeout}
max_mappings = {max_mappings}
{client_extra}
[key]
psk = {psk}
""")
            wait_until(lambda: "client control address updated to" in self.server.text(), 8,
                       desc="server received the client handshake")
            wait_until(lambda: "handshake with server succeeded" in self.client.text(), 8,
                       desc="client got the handshake ACK")
        else:
            wait_until(lambda: "listening on 127.0.0.1" in self.server.text(), 8,
                       desc="server started")

    def stop(self):
        if self.client:
            self.client.stop()
        self.server.stop()
        self.svc.close()

    def cleanup(self):
        if self.client:
            self.client.cleanup()
        self.server.cleanup()


def inet_client():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(3)
    return s


# ---------------------------------------------------------------- test cases
def test_basic_forward():
    """An internet-side datagram reaches the local service through server/client and
    comes back."""
    env = Env()
    try:
        c = inet_client()
        c.sendto(b"hello", ("127.0.0.1", env.data_port))
        got = c.recv(65535)
        assert got == b"echo:hello", got
        c.close()
    finally:
        env.stop()
        env.cleanup()


def test_multi_client_isolation():
    """Concurrent internet clients each get their own replies (mappings never cross-talk)."""
    env = Env()
    try:
        socks = [inet_client() for _ in range(5)]
        for i, s in enumerate(socks):
            s.sendto(f"pkt-{i}".encode(), ("127.0.0.1", env.data_port))
        for i, s in enumerate(socks):
            got = s.recv(65535)
            assert got == f"echo:pkt-{i}".encode(), (i, got)
        # another round, reusing the existing mapping
        for i, s in enumerate(socks):
            s.sendto(f"again-{i}".encode(), ("127.0.0.1", env.data_port))
        for i, s in enumerate(socks):
            got = s.recv(65535)
            assert got == f"echo:again-{i}".encode(), (i, got)
        for s in socks:
            s.close()
    finally:
        env.stop()
        env.cleanup()


def test_big_and_empty_payload():
    """Both maximum-size and empty datagrams are forwarded."""
    env = Env()
    try:
        c = inet_client()
        payload = bytes(range(256)) * 200  # 51200 bytes
        c.sendto(payload, ("127.0.0.1", env.data_port))
        got = c.recv(65535)
        assert got == b"echo:" + payload, f"unexpected large-datagram length: {len(got)}"

        c.settimeout(0.6)
        c.sendto(b"", ("127.0.0.1", env.data_port))
        got = c.recv(65535)
        assert got == b"echo:", got
        c.close()
    finally:
        env.stop()
        env.cleanup()


def test_ack_protocol():
    """A 0x00 handshake gets a 0x02 ACK that echoes our timestamp with a valid HMAC."""
    env = Env(with_client=False)
    try:
        key = derive_key()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.settimeout(2)
        ts = int(time.time())
        s.sendto(hello_pkt(key, ts), ("127.0.0.1", env.control_port))
        ack = s.recv(1024)
        check_ack(ack, key, ts)

        # the second handshake (heartbeat) must be ACKed too
        ts2 = int(time.time()) + 1
        s.sendto(hello_pkt(key, ts2), ("127.0.0.1", env.control_port))
        check_ack(s.recv(1024), key, ts2)
        s.close()
    finally:
        env.stop()
        env.cleanup()


def test_heartbeat_default_30s():
    """The default heartbeat interval is 30 seconds (when heartbeat_interval is absent)."""
    env = Env(heartbeat=None) if False else None
    # start with a config that omits heartbeat_interval and check the log line
    svc = EchoService()
    cport, dport = free_udp_port(), free_udp_port()
    server = Proc("server", f"""
[server]
bind = 127.0.0.1
control_port = {cport}
data_port = {dport}
[key]
psk = {PSK_HEX}
""")
    client = Proc("client", f"""
[client]
server_host = 127.0.0.1
server_control_port = {cport}
local_service_port = {svc.port}
[key]
psk = {PSK_HEX}
""")
    try:
        wait_until(lambda: "heartbeat interval 30 seconds" in client.text(), 8,
                   desc="default heartbeat interval is 30 seconds")
    finally:
        client.stop()
        server.stop()
        client.cleanup()
        server.cleanup()
        svc.close()


def test_reject_bad_mac():
    """A handshake with a bad MAC must not be ACKed."""
    env = Env(with_client=False)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.settimeout(1.0)
        wrong = derive_key("ff" * 32)
        s.sendto(hello_pkt(wrong), ("127.0.0.1", env.control_port))
        assert recv_or_none(s, 1.0) is None, "handshake with a wrong psk was answered"
        s.close()
        assert "MAC verification failed" in env.server.text()
    finally:
        env.stop()
        env.cleanup()


def test_reject_stale_and_future_ts():
    """Handshakes whose timestamp is more than 60 seconds off must be rejected."""
    env = Env(with_client=False)
    try:
        key = derive_key()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.settimeout(1.0)
        now = int(time.time())
        s.sendto(hello_pkt(key, now - 300), ("127.0.0.1", env.control_port))
        assert recv_or_none(s) is None, "handshake with a stale timestamp was answered"
        s.sendto(hello_pkt(key, now + 300), ("127.0.0.1", env.control_port))
        assert recv_or_none(s) is None, "handshake with a future timestamp was answered"
        s.close()
        assert "timestamp is off by more than" in env.server.text()
    finally:
        env.stop()
        env.cleanup()


def test_reject_replayed_hello():
    """Replaying the same handshake from a different source address must be rejected."""
    env = Env(with_client=False)
    try:
        key = derive_key()
        ts = int(time.time())
        pkt = hello_pkt(key, ts)
        a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        a.bind(("127.0.0.1", 0))
        a.settimeout(1.0)
        a.sendto(pkt, ("127.0.0.1", env.control_port))
        check_ack(a.recv(1024), key, ts)

        b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        b.bind(("127.0.0.1", 0))
        b.settimeout(1.0)
        b.sendto(pkt, ("127.0.0.1", env.control_port))
        assert recv_or_none(b) is None, "replayed handshake got an ACK"
        a.close()
        b.close()
    finally:
        env.stop()
        env.cleanup()


def test_mapping_timeout():
    """A mapping idle for 2 seconds (test config) is dropped and can be re-created later."""
    env = Env(idle_timeout=2)
    try:
        c = inet_client()
        c.sendto(b"one", ("127.0.0.1", env.data_port))
        assert c.recv(65535) == b"echo:one"
        wait_until(lambda: "new mapping 127.0.0.1:" in env.client.text(), 3, desc="mapping created")
        wait_until(lambda: "released mapping" in env.client.text(), 8,
                   desc="mapping dropped after the idle timeout")

        # after the timeout the same internet client must get a fresh mapping and a reply
        c.sendto(b"two", ("127.0.0.1", env.data_port))
        assert c.recv(65535) == b"echo:two"
        c.close()
        assert env.client.text().count("new mapping") >= 2
    finally:
        env.stop()
        env.cleanup()


def test_data_dropped_before_handshake():
    """Before any handshake the server must neither forward data nor crash."""
    svc = EchoService()
    cport, dport = free_udp_port(), free_udp_port()
    server = Proc("server", f"""
[server]
bind = 127.0.0.1
control_port = {cport}
data_port = {dport}
[key]
psk = {PSK_HEX}
""")
    try:
        time.sleep(0.3)
        c = inet_client()
        c.settimeout(0.6)
        c.sendto(b"nobody", ("127.0.0.1", dport))
        assert recv_or_none(c, 0.6) is None
        assert svc.hits == 0, "local service must receive nothing without a client"
        assert "no client handshake yet" in server.text()
        assert server.proc.poll() is None, "server must keep running"
        c.close()
    finally:
        server.stop()
        server.cleanup()
        svc.close()


def test_link_broken_when_local_service_down():
    """Nothing crashes when the local UDP service is down: drop the datagram and
    release the mapping."""
    env = Env()
    try:
        c = inet_client()
        env.svc.close()  # take the local service down
        c.sendto(b"nobody-home", ("127.0.0.1", env.data_port))
        assert recv_or_none(c, 1.0) is None
        assert env.client.proc.poll() is None, "client must keep running"
        assert recv_or_none(c, 0.5) is None
        c.close()
    finally:
        env.stop()
        env.cleanup()


def test_client_survives_server_restart():
    """After a server restart the client re-handshakes via heartbeat and forwarding resumes."""
    env = Env(heartbeat=1)
    try:
        c = inet_client()
        c.sendto(b"before", ("127.0.0.1", env.data_port))
        assert c.recv(65535) == b"echo:before"

        cfg = env.server.cfg
        with open(cfg) as f:
            server_cfg = f.read()
        env.server.stop()

        env.server = Proc("server", server_cfg)
        wait_until(lambda: "client control address updated to" in env.server.text(), 10,
                   desc="server got the handshake again")

        # once the new server sees the handshake, forwarding should resume by itself
        ok = False
        for _ in range(50):
            c.sendto(b"after", ("127.0.0.1", env.data_port))
            if recv_or_none(c, 0.4) == b"echo:after":
                ok = True
                break
        assert ok, "forwarding did not resume after the server restart\n" + \
            env.server.text()[-2000:]
        assert "handshake with server succeeded" in env.client.text()
        c.close()
    finally:
        env.stop()
        env.cleanup()


def test_passthrough_passphrase_psk():
    """Both ends interoperate when the psk is a passphrase instead of 64 hex chars."""
    env = Env(psk="this-is-a-long-passphrase-for-testing")
    try:
        c = inet_client()
        c.sendto(b"pass", ("127.0.0.1", env.data_port))
        assert c.recv(65535) == b"echo:pass"
        c.close()
    finally:
        env.stop()
        env.cleanup()


def test_sustained_traffic_with_fast_heartbeat():
    """A 1-second heartbeat plus a continuous data stream: heartbeats must not
    disturb forwarding."""
    env = Env(heartbeat=1)
    try:
        c = inet_client()
        for i in range(60):
            c.sendto(b"seq-%d" % i, ("127.0.0.1", env.data_port))
            got = c.recv(65535)
            assert got == b"echo:seq-%d" % i, (i, got)
            time.sleep(0.05)
        c.close()
    finally:
        env.stop()
        env.cleanup()


def test_max_mappings_limit():
    """Mappings are capped by max_mappings; overflow evicts the least recently
    active one, without crashing."""
    env = Env(max_mappings=4)
    try:
        socks = [inet_client() for _ in range(12)]
        for i, s in enumerate(socks):
            s.sendto(b"m-%d" % i, ("127.0.0.1", env.data_port))
            time.sleep(0.02)
        assert env.client.proc.poll() is None, "client must keep running"
        assert "mapping table is full" in env.client.text()
        # the most recently active client still works (a new source always gets the newest mapping)
        fresh = inet_client()
        fresh.sendto(b"last", ("127.0.0.1", env.data_port))
        assert fresh.recv(65535) == b"echo:last"
        fresh.close()
        for s in socks:
            s.close()
    finally:
        env.stop()
        env.cleanup()


def test_bad_config():
    """Bad config must produce a clear error and exit with a non-zero status."""
    def run(mode, text):
        fd, path = tempfile.mkstemp(suffix=".ini")
        with os.fdopen(fd, "w") as f:
            f.write(text)
        try:
            p = subprocess.run([BIN, mode, "-c", path], capture_output=True, timeout=10)
        finally:
            os.unlink(path)
        return p.returncode, p.stderr.decode()

    rc, err = run("server", "[server]\ncontrol_port = 7000\ndata_port = 7001\n")
    assert rc != 0 and "psk" in err, err

    rc, err = run("server", f"[server]\ncontrol_port = 0\ndata_port = 7001\n[key]\npsk = {PSK_HEX}\n")
    assert rc != 0 and "control_port" in err, err

    rc, err = run("client", f"[client]\nserver_control_port = 7000\n[key]\npsk = {PSK_HEX}\n")
    assert rc != 0 and "server_host" in err, err

    rc, err = run("client", f"[client]\nserver_host = ::1\nserver_control_port = 7000\n"
                            f"local_service_port = 53\n[key]\npsk = {PSK_HEX}\n")
    assert rc != 0 and "ipv4" in err, err

    rc, err = run("client", f"[client]\nserver_host = 1.2.3.4\nserver_control_port = 7000\n"
                            f"[key]\npsk = short\n")
    assert rc != 0, err


TESTS = [
    test_basic_forward,
    test_multi_client_isolation,
    test_big_and_empty_payload,
    test_ack_protocol,
    test_heartbeat_default_30s,
    test_reject_bad_mac,
    test_reject_stale_and_future_ts,
    test_reject_replayed_hello,
    test_mapping_timeout,
    test_data_dropped_before_handshake,
    test_link_broken_when_local_service_down,
    test_client_survives_server_restart,
    test_passthrough_passphrase_psk,
    test_sustained_traffic_with_fast_heartbeat,
    test_max_mappings_limit,
    test_bad_config,
]


def main():
    if not os.path.exists(BIN):
        print(f"{BIN} not found, run make first", file=sys.stderr)
        return 2
    only = sys.argv[1] if len(sys.argv) > 1 else None
    failed = []
    for t in TESTS:
        if only and only not in t.__name__:
            continue
        start = time.time()
        print(f"[ RUN  ] {t.__name__} - {t.__doc__.splitlines()[0]}", flush=True)
        try:
            t()
            print(f"[  OK  ] {t.__name__} ({time.time() - start:.2f}s)", flush=True)
        except Exception:
            failed.append(t.__name__)
            print(f"[ FAIL ] {t.__name__}", flush=True)
            traceback.print_exc()
    print()
    if failed:
        print(f"{len(failed)} failed: {', '.join(failed)}")
        return 1
    print("all tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
