#!/usr/bin/env python3
"""udp forwarder 端到端测试。

需要先编译出 ./udpforwarder（make）。全部用例都在 127.0.0.1 上跑，
不依赖外网，也不需要 root 权限。
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


# ---------------------------------------------------------------- 工具函数
def free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def derive_key(psk_hex=PSK_HEX):
    """复现 proto.c 的 kdf：blake2b(key=master, salt=id_le64, personal=context)。"""
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
    assert len(pkt) == 49, f"ACK 长度应为 49，实际 {len(pkt)}"
    assert pkt[0] == TYPE_ACK, f"ACK 类型字节应为 0x02，实际 {pkt[0]:#04x}"
    body = pkt[1:17]
    cts, sts = struct.unpack(">QQ", body)
    assert cts == client_ts, f"ACK 未回显我方时间戳：{cts} != {client_ts}"
    assert abs(sts - time.time()) <= TS_SKEW + 5, f"ACK 里 server 时间戳异常：{sts}"
    expect = hmac.new(key, body, hashlib.sha256).digest()
    assert expect == pkt[17:], "ACK 的 HMAC 校验失败"


def wait_until(pred, timeout=5.0, interval=0.02, desc=""):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(interval)
    raise AssertionError(f"等待超时：{desc or pred}")


def recv_or_none(sock, timeout=1.0):
    sock.settimeout(timeout)
    try:
        return sock.recv(65535)
    except socket.timeout:
        return None


# ---------------------------------------------------------------- 测试环境
class EchoService:
    """本地 UDP 回显服务，模拟 client 背后的 UDP server。"""

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
            wait_until(lambda: "client 控制地址更新为" in self.server.text(), 8,
                       desc="server 收到 client 握手")
            wait_until(lambda: "握手成功" in self.client.text(), 8,
                       desc="client 收到握手 ACK")
        else:
            wait_until(lambda: "监听 127.0.0.1" in self.server.text(), 8, desc="server 启动")

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


# ---------------------------------------------------------------- 测试用例
def test_basic_forward():
    """互联网侧的 UDP 报文能经 server/client 到达本地服务并原路返回。"""
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
    """多个互联网客户端并发访问，各自拿到自己的回包（映射互不串扰）。"""
    env = Env()
    try:
        socks = [inet_client() for _ in range(5)]
        for i, s in enumerate(socks):
            s.sendto(f"pkt-{i}".encode(), ("127.0.0.1", env.data_port))
        for i, s in enumerate(socks):
            got = s.recv(65535)
            assert got == f"echo:pkt-{i}".encode(), (i, got)
        # 再来一轮，复用已有映射
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
    """最大长度报文与空报文都能转发。"""
    env = Env()
    try:
        c = inet_client()
        payload = bytes(range(256)) * 200  # 51200 字节
        c.sendto(payload, ("127.0.0.1", env.data_port))
        got = c.recv(65535)
        assert got == b"echo:" + payload, f"大报文长度不符: {len(got)}"

        c.settimeout(0.6)
        c.sendto(b"", ("127.0.0.1", env.data_port))
        got = c.recv(65535)
        assert got == b"echo:", got
        c.close()
    finally:
        env.stop()
        env.cleanup()


def test_ack_protocol():
    """0x00 握手能得到 0x02 的 ACK，且回显我方时间戳、HMAC 正确。"""
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

        # 第二次握手（心跳）也要有 ACK
        ts2 = int(time.time()) + 1
        s.sendto(hello_pkt(key, ts2), ("127.0.0.1", env.control_port))
        check_ack(s.recv(1024), key, ts2)
        s.close()
    finally:
        env.stop()
        env.cleanup()


def test_heartbeat_default_30s():
    """默认心跳间隔是 30 秒（配置里不写 heartbeat_interval 时）。"""
    env = Env(heartbeat=None) if False else None
    # 用不带 heartbeat_interval 的配置启动，检查日志里的提示
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
        wait_until(lambda: "心跳间隔 30 秒" in client.text(), 8, desc="默认心跳间隔 30 秒")
    finally:
        client.stop()
        server.stop()
        client.cleanup()
        server.cleanup()
        svc.close()


def test_reject_bad_mac():
    """MAC 错误的握手不应得到 ACK。"""
    env = Env(with_client=False)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.settimeout(1.0)
        wrong = derive_key("ff" * 32)
        s.sendto(hello_pkt(wrong), ("127.0.0.1", env.control_port))
        assert recv_or_none(s, 1.0) is None, "错误 psk 的握手竟收到回应"
        s.close()
        assert "MAC 校验失败" in env.server.text()
    finally:
        env.stop()
        env.cleanup()


def test_reject_stale_and_future_ts():
    """时间戳超出 ±60 秒的握手应被拒绝。"""
    env = Env(with_client=False)
    try:
        key = derive_key()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.settimeout(1.0)
        now = int(time.time())
        s.sendto(hello_pkt(key, now - 300), ("127.0.0.1", env.control_port))
        assert recv_or_none(s) is None, "过期时间戳的握手竟收到回应"
        s.sendto(hello_pkt(key, now + 300), ("127.0.0.1", env.control_port))
        assert recv_or_none(s) is None, "未来时间戳的握手竟收到回应"
        s.close()
        assert "时间戳超出" in env.server.text()
    finally:
        env.stop()
        env.cleanup()


def test_reject_replayed_hello():
    """同一份握手报文（重放）在切换来源地址时应被拒绝。"""
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
        assert recv_or_none(b) is None, "重放的握手报文竟然拿到 ACK"
        a.close()
        b.close()
    finally:
        env.stop()
        env.cleanup()


def test_mapping_timeout():
    """映射 2 秒（测试配置）不活跃后会被清除，之后再访问能重新建立。"""
    env = Env(idle_timeout=2)
    try:
        c = inet_client()
        c.sendto(b"one", ("127.0.0.1", env.data_port))
        assert c.recv(65535) == b"echo:one"
        wait_until(lambda: "新映射 127.0.0.1:" in env.client.text(), 3, desc="映射建立")
        wait_until(lambda: "释放映射" in env.client.text(), 8, desc="映射超时释放")

        # 超时后同一互联网客户端再发包，应重新建立映射并正常收到回包
        c.sendto(b"two", ("127.0.0.1", env.data_port))
        assert c.recv(65535) == b"echo:two"
        c.close()
        assert env.client.text().count("新映射") >= 2
    finally:
        env.stop()
        env.cleanup()


def test_data_dropped_before_handshake():
    """client 还没握手时，server 不应把数据转发出去，也不应崩溃。"""
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
        assert svc.hits == 0, "没有 client 时本地服务不应收到报文"
        assert "还没收到 client 握手" in server.text()
        assert server.proc.poll() is None, "server 不应退出"
        c.close()
    finally:
        server.stop()
        server.cleanup()
        svc.close()


def test_link_broken_when_local_service_down():
    """本地 UDP 服务没监听时不应崩溃：丢弃并释放对应映射。"""
    env = Env()
    try:
        c = inet_client()
        env.svc.close()  # 让本地服务下线
        c.sendto(b"nobody-home", ("127.0.0.1", env.data_port))
        assert recv_or_none(c, 1.0) is None
        assert env.client.proc.poll() is None, "client 不应退出"
        assert recv_or_none(c, 0.5) is None
        c.close()
    finally:
        env.stop()
        env.cleanup()


def test_client_survives_server_restart():
    """server 重启后，client 靠心跳重新完成握手，转发自动恢复。"""
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
        wait_until(lambda: "client 控制地址更新为" in env.server.text(), 10,
                   desc="server 再次收到握手")

        # 新 server 收到握手后，转发应自动恢复
        ok = False
        for _ in range(50):
            c.sendto(b"after", ("127.0.0.1", env.data_port))
            if recv_or_none(c, 0.4) == b"echo:after":
                ok = True
                break
        assert ok, "server 重启后转发没有恢复\n" + env.server.text()[-2000:]
        assert "握手成功" in env.client.text()
        c.close()
    finally:
        env.stop()
        env.cleanup()


def test_passthrough_passphrase_psk():
    """psk 写成口令（非 64 hex）时两端仍能互通。"""
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
    """1 秒心跳 + 持续数据流，心跳不应干扰数据转发。"""
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
    """映射数量受 max_mappings 限制，超出时淘汰最久不活跃的映射且不崩溃。"""
    env = Env(max_mappings=4)
    try:
        socks = [inet_client() for _ in range(12)]
        for i, s in enumerate(socks):
            s.sendto(b"m-%d" % i, ("127.0.0.1", env.data_port))
            time.sleep(0.02)
        assert env.client.proc.poll() is None, "client 不应退出"
        assert "映射表已满" in env.client.text()
        # 最近活跃的客户端仍然能正常收发（新来源一定会拿到最新的映射）
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
    """配置错误要给出明确报错并以非零状态退出。"""
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
        print(f"找不到 {BIN}，请先 make", file=sys.stderr)
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
        print(f"失败 {len(failed)} 个: {', '.join(failed)}")
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
