#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import queue
import re
import select
import socket
import subprocess
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


DEFAULT_CONFIG: dict[str, Any] = {
    "enabled": True,
    "subscription_token": "",
    "proxy_username_prefix": "am",
    "proxy_password": "",
    "public_host": "",
    "socks_host": "0.0.0.0",
    "socks_port": 7930,
    "http_host": "0.0.0.0",
    "http_port": 0,
    "http_enabled": False,
    "max_tunnels": 8,
    "hot_per_group": 4,
    "residential_slots": 4,
    "idle_timeout_seconds": 900,
    "prewarm_interval_seconds": 180,
    "openvpn_timeout_seconds": 35,
    "health_url": "http://www.gstatic.com/generate_204",
    "refresh_verify_limit": 40,
    "subscription_requires_bridge_verified": True,
    "verified_ttl_seconds": 1800,
}


OpenvpnCommandBuilder = Callable[[str, bool, str], list[str]]


def _random_token(length: int = 32) -> str:
    import random
    import string

    chars = string.ascii_letters + string.digits
    return "".join(random.choices(chars, k=length))


def _parse_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(exist_ok=True, parents=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def _yaml_scalar(value: Any) -> str:
    text = str(value)
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _safe_display_part(value: Any, fallback: str = "-") -> str:
    text = str(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    return text if text else fallback


def _node_latency(node: dict[str, Any]) -> int:
    latency = _parse_int(node.get("latency_ms"))
    return latency if latency > 0 else 999999


def _is_residential(node: dict[str, Any]) -> bool:
    ip_type = str(node.get("ip_type") or "").lower()
    quality = str(node.get("quality") or "").lower()
    return ip_type == "residential" and quality in ("", "normal", "residential")


def node_username(node_id: str, prefix: str = "am") -> str:
    digest = hashlib.sha1(node_id.encode("utf-8", errors="replace")).hexdigest()[:18]
    return f"{prefix}_{digest}"


def resolve_dns_over_interface(host: str, interface: str, dns_server: str = "8.8.8.8", timeout: float = 3.0) -> str | None:
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass

    import random

    tx_id = random.getrandbits(16).to_bytes(2, "big")
    packet = tx_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b""
    for part in host.split("."):
        if not part:
            continue
        part_bytes = part.encode("idna")
        qname += len(part_bytes).to_bytes(1, "big") + part_bytes
    packet += qname + b"\x00\x00\x01\x00\x01"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        bind_opt = getattr(socket, "SO_BINDTODEVICE", 25)
        sock.setsockopt(socket.SOL_SOCKET, bind_opt, interface.encode("utf-8"))
        sock.sendto(packet, (dns_server, 53))
        resp, _ = sock.recvfrom(2048)
    except Exception:
        return None
    finally:
        sock.close()

    if len(resp) < 12 or resp[:2] != tx_id or (resp[3] & 0x0F) != 0:
        return None

    offset = 12
    while offset < len(resp):
        length = resp[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            offset += 2
            break
        offset += 1 + length
    offset += 4

    answers_count = int.from_bytes(resp[6:8], "big")
    for _ in range(answers_count):
        if offset >= len(resp):
            break
        while offset < len(resp):
            length = resp[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                offset += 2
                break
            offset += 1 + length
        if offset + 10 > len(resp):
            break
        atype = int.from_bytes(resp[offset : offset + 2], "big")
        aclass = int.from_bytes(resp[offset + 2 : offset + 4], "big")
        rdlength = int.from_bytes(resp[offset + 8 : offset + 10], "big")
        offset += 10
        if offset + rdlength > len(resp):
            break
        if atype == 1 and aclass == 1 and rdlength == 4:
            return socket.inet_ntoa(resp[offset : offset + 4])
        offset += rdlength
    return None


def create_bound_connection(interface: str, address: tuple[str, int], timeout: float = 20) -> socket.socket:
    host, port = address
    resolved_ip = resolve_dns_over_interface(host, interface)
    if resolved_ip:
        host = resolved_ip

    bind_opt = getattr(socket, "SO_BINDTODEVICE", 25)
    last_error: OSError | None = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, _canonname, sa = res
        sock = socket.socket(af, socktype, proto)
        try:
            sock.settimeout(timeout)
            sock.setsockopt(socket.SOL_SOCKET, bind_opt, interface.encode("utf-8"))
            sock.connect(sa)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    if last_error is not None:
        raise last_error
    raise OSError("getaddrinfo returned no usable address")


def relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 120)
        if errored:
            return
        for source in readable:
            target = right if source is left else left
            data = source.recv(65536)
            if not data:
                return
            target.sendall(data)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Unexpected disconnect")
        data += chunk
    return data


@dataclass
class TunnelState:
    node_id: str
    interface: str
    table: int
    process: subprocess.Popen[str]
    last_used: float
    started_at: float


class ClashBridge:
    def __init__(
        self,
        data_dir: Path,
        config_dir: Path,
        nodes_file: Path,
        openvpn_command_builder: OpenvpnCommandBuilder,
    ) -> None:
        self.data_dir = data_dir
        self.config_dir = config_dir
        self.nodes_file = nodes_file
        self.config_file = data_dir / "clash_bridge.json"
        self.openvpn_command_builder = openvpn_command_builder
        self.lock = threading.RLock()
        self.tunnels: dict[str, TunnelState] = {}
        self.running = False
        self.refresh_lock = threading.Lock()
        self.refresh_running = False
        self.refresh_status = "idle"

    def load_config(self) -> dict[str, Any]:
        config = DEFAULT_CONFIG.copy()
        saved = _read_json(self.config_file, {})
        if isinstance(saved, dict):
            config.update(saved)
        changed = False
        if not config.get("subscription_token"):
            config["subscription_token"] = _random_token(32)
            changed = True
        if not config.get("proxy_password"):
            config["proxy_password"] = _random_token(18)
            changed = True
        if changed or not self.config_file.exists():
            _write_json(self.config_file, config)
            try:
                self.config_file.chmod(0o600)
            except OSError:
                pass
        return config

    def enabled(self) -> bool:
        return bool(self.load_config().get("enabled", True))

    def public_host(self, request_host: str = "") -> str:
        cfg = self.load_config()
        explicit = str(cfg.get("public_host") or "").strip()
        if explicit:
            return explicit
        if request_host:
            return request_host.split(":", 1)[0]
        public_ip_file = self.data_dir / "public_ip.txt"
        try:
            value = public_ip_file.read_text(encoding="utf-8").strip()
            if value:
                return value
        except OSError:
            pass
        return "127.0.0.1"

    def available_nodes(self) -> list[dict[str, Any]]:
        nodes = self._raw_residential_nodes()
        cfg = self.load_config()
        if not bool(cfg.get("subscription_requires_bridge_verified", True)):
            return nodes
        ttl = max(60, _parse_int(cfg.get("verified_ttl_seconds"), 1800))
        now = time.time()
        return [
            node for node in nodes
            if node.get("clash_probe_status") == "available"
            and now - float(node.get("clash_probed_at") or 0) <= ttl
        ]

    def _raw_available_nodes(self) -> list[dict[str, Any]]:
        nodes = _read_json(self.nodes_file, [])
        if not isinstance(nodes, list):
            return []
        result = []
        for node in nodes:
            if not isinstance(node, dict):
                continue
            if node.get("probe_status") == "available" or node.get("active"):
                result.append(node)
        return sorted(result, key=lambda n: (_node_latency(n), -_parse_int(n.get("score"))))

    def _raw_residential_nodes(self) -> list[dict[str, Any]]:
        return [node for node in self._raw_available_nodes() if _is_residential(node)]

    def node_by_username(self, username: str) -> dict[str, Any] | None:
        prefix = str(self.load_config().get("proxy_username_prefix") or "am")
        for node in self.available_nodes():
            node_id = str(node.get("id") or "")
            if node_id and node_username(node_id, prefix) == username:
                return node
        return None

    def check_subscription_token(self, token: str) -> bool:
        expected = str(self.load_config().get("subscription_token") or "")
        return bool(expected and token and token == expected)

    def render_subscription(self, request_host: str = "") -> str:
        cfg = self.load_config()
        host = self.public_host(request_host)
        socks_port = _parse_int(cfg.get("socks_port"), 7930)
        password = str(cfg.get("proxy_password") or "")
        prefix = str(cfg.get("proxy_username_prefix") or "am")
        health_url = str(cfg.get("health_url") or DEFAULT_CONFIG["health_url"])
        residential_slots = max(1, _parse_int(cfg.get("residential_slots"), 4))

        residential = self.available_nodes()[:residential_slots]
        res_names = self._proxy_names_for_nodes(residential)

        lines = [
            "mixed-port: 7890",
            "allow-lan: false",
            "mode: rule",
            "log-level: info",
            "dns:",
            "  enable: true",
            "  enhanced-mode: fake-ip",
            "  nameserver:",
            "    - 223.5.5.5",
            "    - 119.29.29.29",
            "proxies:",
        ]

        if not residential:
            lines[-1] = "proxies: []"
        else:
            used_names: set[str] = set()
            for node in residential:
                name = self._proxy_name(node, "S")
                if name in used_names:
                    continue
                used_names.add(name)
                username = node_username(str(node.get("id") or ""), prefix)
                lines.extend(
                    [
                        f"  - name: {_yaml_scalar(name)}",
                        "    type: socks5",
                        f"    server: {_yaml_scalar(host)}",
                        f"    port: {socks_port}",
                        f"    username: {_yaml_scalar(username)}",
                        f"    password: {_yaml_scalar(password)}",
                    ]
                )

        lines.append("proxy-groups:")
        group_type = "url-test" if res_names else "select"
        self._append_group(lines, "住宅IP-优选", group_type, res_names, health_url)

        lines.extend(["rules:", "  - MATCH,住宅IP-优选"])
        return "\n".join(lines) + "\n"

    def refresh_status_snapshot(self) -> dict[str, Any]:
        with self.refresh_lock:
            return {
                "running": self.refresh_running,
                "message": self.refresh_status,
            }

    def residential_status_snapshot(self, request_host: str = "") -> dict[str, Any]:
        cfg = self.load_config()
        target = max(1, _parse_int(cfg.get("residential_slots"), 4))
        candidates = self._raw_residential_nodes()
        verified = self.available_nodes()
        verified_ids = {str(node.get("id") or "") for node in verified}
        network = self._managed_network_snapshot()
        now = time.time()

        with self.lock:
            active_tunnels = {
                node_id: state
                for node_id, state in self.tunnels.items()
                if state.process.poll() is None
            }

        rows: list[dict[str, Any]] = []
        for node in candidates:
            node_id = str(node.get("id") or "")
            if not node_id:
                continue
            tunnel = active_tunnels.get(node_id)
            interface = tunnel.interface if tunnel else str(node.get("clash_interface") or "")
            table = tunnel.table if tunnel else _parse_int(node.get("clash_table"))
            rule = network["rules"].get(interface, {}) if interface else {}
            route = network["routes"].get(str(table), "") if table else ""
            interface_exists = bool(interface and interface in network["interfaces"])
            route_exists = bool(interface and route and f"dev {interface}" in route)
            rule_exists = bool(rule.get("exists"))
            rule_detached = bool(rule.get("detached"))
            probed_at = float(node.get("clash_probed_at") or 0)
            rows.append(
                {
                    "id": node_id,
                    "country": node.get("country") or "",
                    "country_short": node.get("country_short") or "",
                    "ip": node.get("ip") or node.get("remote_host") or "",
                    "remote_port": node.get("remote_port") or "",
                    "latency_ms": _parse_int(node.get("latency_ms")),
                    "score": _parse_int(node.get("score")),
                    "ip_type": node.get("ip_type") or "",
                    "quality": node.get("quality") or "",
                    "probe_status": node.get("probe_status") or "",
                    "clash_probe_status": node.get("clash_probe_status") or "",
                    "clash_probe_message": node.get("clash_probe_message") or "",
                    "clash_probed_at": probed_at,
                    "clash_probe_age_seconds": int(now - probed_at) if probed_at else 0,
                    "subscribable": node_id in verified_ids,
                    "tunnel_running": bool(tunnel),
                    "interface": interface,
                    "table": table,
                    "interface_exists": interface_exists,
                    "route_exists": route_exists,
                    "rule_exists": rule_exists,
                    "rule_detached": rule_detached,
                    "route": route,
                    "rule": rule.get("raw", ""),
                }
            )

        active_tunnel_rows = []
        for node_id, tunnel in active_tunnels.items():
            interface_info = network["interfaces"].get(tunnel.interface, {})
            rule = network["rules"].get(tunnel.interface, {})
            route = network["routes"].get(str(tunnel.table), "")
            active_tunnel_rows.append(
                {
                    "node_id": node_id,
                    "interface": tunnel.interface,
                    "table": tunnel.table,
                    "interface_exists": tunnel.interface in network["interfaces"],
                    "interface_state": interface_info.get("state", ""),
                    "route_exists": bool(route and f"dev {tunnel.interface}" in route),
                    "rule_exists": bool(rule.get("exists")),
                    "rule_detached": bool(rule.get("detached")),
                    "started_at": tunnel.started_at,
                    "last_used": tunnel.last_used,
                }
            )

        rows.sort(
            key=lambda item: (
                0 if item["subscribable"] else 1,
                0 if item["tunnel_running"] else 1,
                item["latency_ms"] if item["latency_ms"] > 0 else 999999,
                -item["score"],
            )
        )

        with self.refresh_lock:
            running = self.refresh_running
            message = self.refresh_status

        detached_count = sum(1 for rule in network["rules"].values() if rule.get("detached"))
        return {
            "ok": True,
            "running": running,
            "message": message,
            "counts": {
                "target": target,
                "residential_candidates": len(candidates),
                "verified": len(verified),
                "subscription": min(len(verified), target),
                "active_tunnels": len(active_tunnels),
                "managed_interfaces": len(network["interfaces"]),
                "detached_rules": detached_count,
            },
            "subscription": {
                "ready": bool(verified),
                "node_count": min(len(verified), target),
                "host": self.public_host(request_host),
                "socks_port": _parse_int(cfg.get("socks_port"), 7930),
                "token": str(cfg.get("subscription_token") or ""),
            },
            "tunnels": active_tunnel_rows,
            "nodes": rows,
        }

    def trigger_refresh(self) -> dict[str, Any]:
        with self.refresh_lock:
            if self.refresh_running:
                return {"ok": True, "started": False, "message": self.refresh_status}
            self.refresh_running = True
            self.refresh_status = "正在后台验证住宅 IP 节点..."
        threading.Thread(target=self._refresh_worker, daemon=True).start()
        return {"ok": True, "started": True, "message": self.refresh_status}

    def trigger_repair(self) -> dict[str, Any]:
        with self.refresh_lock:
            if self.refresh_running:
                return {"ok": True, "started": False, "message": self.refresh_status}
            self.refresh_running = True
            self.refresh_status = "正在诊断补齐住宅 IP 热池..."
        threading.Thread(target=self._refresh_worker, daemon=True).start()
        return {"ok": True, "started": True, "message": self.refresh_status}

    def _refresh_worker(self) -> None:
        checked = 0
        failed = 0
        passed = 0
        try:
            with self.lock:
                self._cleanup_idle_locked()
                self._cleanup_managed_policy_routing(preserve_active=True)
                self._reconcile_active_policy_routing_locked()
            cfg = self.load_config()
            limit = max(1, _parse_int(cfg.get("refresh_verify_limit"), 20))
            target = max(1, _parse_int(cfg.get("residential_slots"), 4))
            nodes = self._raw_residential_nodes()[:limit]
            if not nodes:
                with self.refresh_lock:
                    self.refresh_status = "没有可验证的住宅 IP 候选节点"
                return
            for node in nodes:
                if passed >= target:
                    break
                node_id = str(node.get("id") or "")
                if not node_id:
                    continue
                checked += 1
                with self.refresh_lock:
                    self.refresh_status = f"正在验证住宅 IP {checked}/{len(nodes)}，已通过 {passed}/{target}: {node_id}"
                try:
                    interface = self.ensure_tunnel(node_id)
                    ok, message = self._check_tunnel_health(interface)
                    if not ok:
                        self._mark_unavailable(node_id, message)
                        raise RuntimeError(message)
                    self._mark_clash_available(node_id, "Clash bridge health check ok", interface)
                    passed += 1
                except Exception as exc:
                    failed += 1
                    print(f"[ClashBridge] refresh verification failed for {node_id}: {exc}", flush=True)
            with self.refresh_lock:
                self.refresh_status = f"住宅 IP 验证完成：已检查 {checked} 个，通过 {passed} 个，失败 {failed} 个；请在 Clash 客户端更新订阅"
        except Exception as exc:
            with self.refresh_lock:
                self.refresh_status = f"住宅 IP 验证异常: {exc}"
        finally:
            with self.refresh_lock:
                self.refresh_running = False

    def _proxy_names_for_nodes(self, nodes: list[dict[str, Any]]) -> list[str]:
        names: list[str] = []
        for node in nodes:
            names.append(self._proxy_name(node, "S"))
        return names

    def _proxy_name(self, node: dict[str, Any], suffix: str) -> str:
        country = _safe_display_part(node.get("country_short") or node.get("country"), "XX")
        ip_type = _safe_display_part(node.get("ip_type") or node.get("quality"), "unknown")
        ip = _safe_display_part(node.get("ip") or node.get("remote_host"), "node")
        latency = _parse_int(node.get("latency_ms"))
        latency_text = f"{latency}ms" if latency > 0 else "NA"
        short_hash = hashlib.sha1(str(node.get("id") or ip).encode("utf-8", errors="replace")).hexdigest()[:6]
        return f"{country} {ip_type} {latency_text} {ip} {short_hash}-{suffix}"

    def _append_group(self, lines: list[str], name: str, group_type: str, proxies: list[str], health_url: str) -> None:
        lines.append(f"  - name: {_yaml_scalar(name)}")
        lines.append(f"    type: {group_type}")
        if group_type == "url-test":
            lines.append(f"    url: {_yaml_scalar(health_url)}")
            lines.append("    interval: 300")
            lines.append("    tolerance: 80")
        lines.append("    proxies:")
        if proxies:
            for proxy_name in proxies:
                lines.append(f"      - {_yaml_scalar(proxy_name)}")
        else:
            lines.append(f"      - {_yaml_scalar('REJECT')}")

    def start(self) -> None:
        if not self.enabled():
            print("[ClashBridge] disabled", flush=True)
            return
        self.running = True
        cfg = self.load_config()
        self._cleanup_managed_policy_routing()
        threading.Thread(target=self._maintenance_loop, daemon=True).start()
        socks_port = _parse_int(cfg.get("socks_port"), 7930)
        if socks_port > 0:
            threading.Thread(
                target=self._start_socks_server,
                args=(str(cfg.get("socks_host") or "0.0.0.0"), socks_port),
                daemon=True,
            ).start()
        http_port = _parse_int(cfg.get("http_port"), 0)
        if bool(cfg.get("http_enabled", False)) and http_port > 0:
            threading.Thread(
                target=self._start_http_server,
                args=(str(cfg.get("http_host") or "0.0.0.0"), http_port),
                daemon=True,
            ).start()

    def ensure_tunnel(self, node_id: str) -> str:
        with self.lock:
            state = self.tunnels.get(node_id)
            if state and state.process.poll() is None:
                state.last_used = time.time()
                return state.interface
            if state:
                self._cleanup_tunnel_locked(node_id, "process exited")

            self._cleanup_idle_locked()
            self._enforce_capacity_locked()

            node = self._get_available_node(node_id)
            if not node:
                raise RuntimeError(f"node is not available: {node_id}")
            interface = self._next_interface_locked()
            table = 110 + _parse_int(interface.removeprefix("tun"), 10)
            process = self._start_openvpn(node, interface)
            self._setup_policy_routing(interface, table)
            ok, message = self._check_tunnel_health(interface)
            if not ok:
                self._cleanup_policy_routing(interface, table)
                self._stop_process(process)
                self._mark_unavailable(node_id, message)
                raise RuntimeError(message)
            self.tunnels[node_id] = TunnelState(
                node_id=node_id,
                interface=interface,
                table=table,
                process=process,
                last_used=time.time(),
                started_at=time.time(),
            )
            print(f"[ClashBridge] tunnel ready: {node_id} via {interface}", flush=True)
            return interface

    def create_connection(self, node_id: str, address: tuple[str, int]) -> socket.socket:
        interface = self.ensure_tunnel(node_id)
        return create_bound_connection(interface, address)

    def _get_available_node(self, node_id: str) -> dict[str, Any] | None:
        for node in self._raw_available_nodes():
            if str(node.get("id") or "") == node_id:
                return node
        return None

    def _next_interface_locked(self) -> str:
        used = {state.interface for state in self.tunnels.values()}
        max_tunnels = max(1, _parse_int(self.load_config().get("max_tunnels"), 8))
        for idx in range(10, 10 + max_tunnels * 4):
            name = f"tun{idx}"
            if name not in used:
                return name
        return f"tun{int(time.time()) % 1000 + 100}"

    def _start_openvpn(self, node: dict[str, Any], interface: str) -> subprocess.Popen[str]:
        config_text = str(node.get("config_text") or "")
        if not config_text:
            raise RuntimeError("node config is empty")
        node_id = str(node.get("id") or "")
        config_file = self.config_dir / f"clash_{node_id}.ovpn"
        config_file.write_text(config_text, encoding="utf-8")
        command = self.openvpn_command_builder(str(config_file), True, interface)
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(self.data_dir.parent),
            )
        except FileNotFoundError as exc:
            self._mark_unavailable(node_id, "openvpn command not found")
            raise RuntimeError("openvpn command not found") from exc
        except OSError as exc:
            self._mark_unavailable(node_id, f"openvpn start failed: {exc}")
            raise

        ok, message = self._wait_openvpn_ready(process, node_id, interface)
        if not ok:
            self._stop_process(process)
            self._mark_unavailable(node_id, message)
            raise RuntimeError(message)
        return process

    def _check_tunnel_health(self, interface: str) -> tuple[bool, str]:
        cfg = self.load_config()
        health_url = str(cfg.get("health_url") or DEFAULT_CONFIG["health_url"])
        parsed = urllib.parse.urlsplit(health_url)
        if parsed.scheme not in ("http", "") or not parsed.hostname:
            return True, "health check skipped"
        port = parsed.port or 80
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        host_header = parsed.hostname
        if parsed.port:
            host_header = f"{host_header}:{parsed.port}"
        try:
            sock = create_bound_connection(interface, (parsed.hostname, port), timeout=8)
            try:
                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host_header}\r\n"
                    "User-Agent: AimiliVPN-ClashBridge/1.0\r\n"
                    "Connection: close\r\n\r\n"
                )
                sock.sendall(request.encode("ascii", errors="ignore"))
                response = sock.recv(256)
                if response.startswith(b"HTTP/1."):
                    return True, "health check ok"
                return False, "tunnel health check returned invalid response"
            finally:
                sock.close()
        except Exception as exc:
            return False, f"tunnel health check failed on {interface}: {exc}"

    def _wait_openvpn_ready(self, process: subprocess.Popen[str], node_id: str, interface: str) -> tuple[bool, str]:
        cfg = self.load_config()
        timeout = max(5, _parse_int(cfg.get("openvpn_timeout_seconds"), 35))
        lines: queue.Queue[str | None] = queue.Queue()
        startup_done = [False]

        def reader() -> None:
            assert process.stdout is not None
            for line in process.stdout:
                text = line.rstrip()
                if not startup_done[0]:
                    lines.put(text)
                else:
                    print(f"[ClashBridge:{interface}:{node_id}] {text}", flush=True)
            if not startup_done[0]:
                lines.put(None)

        threading.Thread(target=reader, daemon=True).start()
        started = time.time()
        tail: list[str] = []
        message = f"OpenVPN timeout after {timeout}s"
        while time.time() - started < timeout:
            try:
                line = lines.get(timeout=0.5)
            except queue.Empty:
                if process.poll() is not None:
                    break
                continue
            if line is None:
                break
            if line:
                tail.append(line)
                tail = tail[-8:]
            lower = line.lower()
            if "initialization sequence completed" in lower:
                startup_done[0] = True
                return True, f"connected in {int((time.time() - started) * 1000)} ms"
            if "auth_failed" in lower or "authentication failed" in lower:
                message = "AUTH_FAILED"
                break
            if "cannot ioctl" in lower or "fatal error" in lower:
                message = line[-220:]
                break
        if tail:
            message = tail[-1][-220:]
        startup_done[0] = True
        return False, message

    def _setup_policy_routing(self, interface: str, table: int) -> None:
        if not os.name == "posix":
            return
        subprocess.run(["ip", "rule", "del", "oif", interface, "table", str(table)], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "flush", "table", str(table)], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "add", "default", "dev", interface, "table", str(table)], check=True, timeout=2)
        subprocess.run(["ip", "rule", "add", "oif", interface, "table", str(table)], check=True, timeout=2)

    def _cleanup_policy_routing(self, interface: str, table: int) -> None:
        if not os.name == "posix":
            return
        subprocess.run(["ip", "rule", "del", "oif", interface, "table", str(table)], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "flush", "table", str(table)], capture_output=True, timeout=2)

    def _managed_interface_tables(self) -> list[tuple[str, int]]:
        max_tunnels = max(1, _parse_int(self.load_config().get("max_tunnels"), 8))
        return [(f"tun{idx}", 110 + idx) for idx in range(10, 10 + max_tunnels * 4)]

    def _cleanup_managed_policy_routing(self, preserve_active: bool = False) -> None:
        if not os.name == "posix":
            return
        active_interfaces: set[str] = set()
        if preserve_active:
            active_interfaces = {
                state.interface
                for state in self.tunnels.values()
                if state.process.poll() is None
            }
        for interface, table in self._managed_interface_tables():
            if interface in active_interfaces:
                continue
            subprocess.run(["ip", "rule", "del", "oif", interface, "table", str(table)], capture_output=True, timeout=2)
            subprocess.run(["ip", "route", "flush", "table", str(table)], capture_output=True, timeout=2)

    def _reconcile_active_policy_routing_locked(self) -> None:
        for state in list(self.tunnels.values()):
            if state.process.poll() is None:
                try:
                    self._setup_policy_routing(state.interface, state.table)
                except Exception as exc:
                    print(f"[ClashBridge] failed to reconcile policy routing for {state.interface}: {exc}", flush=True)

    def _ip_output(self, args: list[str], timeout: float = 1.5) -> str:
        if not os.name == "posix":
            return ""
        try:
            proc = subprocess.run(["ip", *args], capture_output=True, text=True, timeout=timeout)
            return proc.stdout or ""
        except Exception:
            return ""

    def _managed_network_snapshot(self) -> dict[str, Any]:
        interfaces: dict[str, dict[str, Any]] = {}
        managed = self._managed_interface_tables()
        managed_names = {interface for interface, _ in managed}
        for line in self._ip_output(["-br", "addr", "show"]).splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            name = parts[0].split("@", 1)[0]
            if name in managed_names:
                interfaces[name] = {
                    "name": name,
                    "state": parts[1],
                    "addresses": parts[2:],
                    "raw": line,
                }

        rules: dict[str, dict[str, Any]] = {}
        rule_lines = self._ip_output(["rule", "show"]).splitlines()
        for interface, table in managed:
            raw = next((line for line in rule_lines if f"oif {interface}" in line), "")
            if raw:
                lookup_text = f"lookup {table}"
                rules[interface] = {
                    "exists": lookup_text in raw or f"table {table}" in raw,
                    "detached": "[detached]" in raw,
                    "table": table,
                    "raw": raw,
                }

        routes: dict[str, str] = {}
        route_tables = {str(table) for _, table in managed}
        for table in route_tables:
            routes[table] = self._ip_output(["route", "show", "table", table]).strip()
        return {"interfaces": interfaces, "rules": rules, "routes": routes}

    def _stop_process(self, process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()

    def _cleanup_tunnel_locked(self, node_id: str, reason: str) -> None:
        state = self.tunnels.pop(node_id, None)
        if not state:
            return
        print(f"[ClashBridge] cleanup tunnel {node_id} ({state.interface}): {reason}", flush=True)
        self._cleanup_policy_routing(state.interface, state.table)
        self._stop_process(state.process)

    def _cleanup_idle_locked(self) -> None:
        idle_timeout = max(60, _parse_int(self.load_config().get("idle_timeout_seconds"), 900))
        now = time.time()
        for node_id, state in list(self.tunnels.items()):
            if state.process.poll() is not None:
                self._cleanup_tunnel_locked(node_id, "process exited")
            elif now - state.last_used > idle_timeout:
                self._cleanup_tunnel_locked(node_id, "idle timeout")

    def _enforce_capacity_locked(self) -> None:
        max_tunnels = max(1, _parse_int(self.load_config().get("max_tunnels"), 8))
        while len(self.tunnels) >= max_tunnels:
            oldest = min(self.tunnels.values(), key=lambda state: state.last_used)
            self._cleanup_tunnel_locked(oldest.node_id, "capacity limit")

    def _mark_unavailable(self, node_id: str, message: str) -> None:
        nodes = _read_json(self.nodes_file, [])
        if not isinstance(nodes, list):
            return
        changed = False
        for node in nodes:
            if isinstance(node, dict) and str(node.get("id") or "") == node_id:
                node["probe_status"] = "unavailable"
                node["probe_message"] = f"Clash bridge failed: {message}"
                node["clash_probe_status"] = "unavailable"
                node["clash_probe_message"] = message
                node["clash_probed_at"] = time.time()
                node["probed_at"] = time.time()
                changed = True
        if changed:
            _write_json(self.nodes_file, nodes)

    def _mark_clash_available(self, node_id: str, message: str, interface: str = "") -> None:
        nodes = _read_json(self.nodes_file, [])
        if not isinstance(nodes, list):
            return
        changed = False
        for node in nodes:
            if isinstance(node, dict) and str(node.get("id") or "") == node_id:
                node["clash_probe_status"] = "available"
                node["clash_probe_message"] = message
                node["clash_probed_at"] = time.time()
                if interface:
                    node["clash_interface"] = interface
                    node["clash_table"] = 110 + _parse_int(interface.removeprefix("tun"), 0)
                changed = True
        if changed:
            _write_json(self.nodes_file, nodes)

    def _maintenance_loop(self) -> None:
        while self.running:
            try:
                with self.lock:
                    self._cleanup_idle_locked()
                if len(self.available_nodes()) < max(1, _parse_int(self.load_config().get("residential_slots"), 4)):
                    self.trigger_refresh()
                self._prewarm_hot_nodes()
            except Exception as exc:
                print(f"[ClashBridge] maintenance error: {exc}", flush=True)
            time.sleep(max(30, _parse_int(self.load_config().get("prewarm_interval_seconds"), 180)))

    def _prewarm_hot_nodes(self) -> None:
        cfg = self.load_config()
        slots = max(0, _parse_int(cfg.get("residential_slots"), 4))
        if slots <= 0:
            return
        for node in self.available_nodes()[:slots]:
            node_id = str(node.get("id") or "")
            if not node_id:
                continue
            try:
                self.ensure_tunnel(node_id)
            except Exception as exc:
                print(f"[ClashBridge] prewarm failed for {node_id}: {exc}", flush=True)

    def _authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        cfg = self.load_config()
        expected_password = str(cfg.get("proxy_password") or "")
        if not expected_password or password != expected_password:
            return None
        return self.node_by_username(username)

    def _start_socks_server(self, host: str, port: int) -> None:
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((host, port))
            server.listen(256)
            print(f"[ClashBridge] SOCKS5 listening on {host}:{port}", flush=True)
        except Exception as exc:
            print(f"[ClashBridge] failed to start SOCKS5 on {host}:{port}: {exc}", flush=True)
            return
        while True:
            client, address = server.accept()
            threading.Thread(target=self._handle_socks_client, args=(client, address), daemon=True).start()

    def _handle_socks_client(self, client: socket.socket, address: tuple[str, int]) -> None:
        upstream = None
        try:
            client.settimeout(30)
            version = recv_exact(client, 1)[0]
            if version != 5:
                return
            methods_count = recv_exact(client, 1)[0]
            methods = recv_exact(client, methods_count)
            if b"\x02" not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x02")
            auth_version = recv_exact(client, 1)[0]
            if auth_version != 1:
                return
            username = recv_exact(client, recv_exact(client, 1)[0]).decode("utf-8", errors="replace")
            password = recv_exact(client, recv_exact(client, 1)[0]).decode("utf-8", errors="replace")
            node = self._authenticate(username, password)
            if not node:
                print(f"[ClashBridge] SOCKS auth failed from {address}: {username}", flush=True)
                client.sendall(b"\x01\x01")
                return
            client.sendall(b"\x01\x00")
            version, command, _reserved, address_type = recv_exact(client, 4)
            if version != 5 or command != 1:
                client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            if address_type == 1:
                host = socket.inet_ntoa(recv_exact(client, 4))
            elif address_type == 3:
                host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
            elif address_type == 4:
                host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
            else:
                client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            port = int.from_bytes(recv_exact(client, 2), "big")
            upstream = self.create_connection(str(node.get("id") or ""), (host, port))
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            relay(client, upstream)
        except Exception as exc:
            print(f"[ClashBridge] SOCKS client {address} failed: {exc}", flush=True)
            try:
                client.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
            except OSError:
                pass
        finally:
            client.close()
            if upstream:
                upstream.close()

    def _start_http_server(self, host: str, port: int) -> None:
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((host, port))
            server.listen(256)
            print(f"[ClashBridge] HTTP proxy listening on {host}:{port}", flush=True)
        except Exception as exc:
            print(f"[ClashBridge] failed to start HTTP proxy on {host}:{port}: {exc}", flush=True)
            return
        while True:
            client, address = server.accept()
            threading.Thread(target=self._handle_http_client, args=(client, address), daemon=True).start()

    def _handle_http_client(self, client: socket.socket, address: tuple[str, int]) -> None:
        upstream = None
        try:
            client.settimeout(30)
            header = b""
            while b"\r\n\r\n" not in header and len(header) < 65536:
                chunk = client.recv(4096)
                if not chunk:
                    return
                header += chunk
            head, rest = header.split(b"\r\n\r\n", 1)
            lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
            method, target, version = lines[0].split(" ", 2)
            node = self._authenticate_http(lines)
            if not node:
                print(f"[ClashBridge] HTTP auth failed from {address}", flush=True)
                client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"AimiliVPN\"\r\nContent-Length: 0\r\n\r\n")
                return
            node_id = str(node.get("id") or "")
            if method.upper() == "CONNECT":
                host, _sep, port_text = target.partition(":")
                port = _parse_int(port_text, 443)
                upstream = self.create_connection(node_id, (host, port))
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if rest:
                    upstream.sendall(rest)
                relay(client, upstream)
                return

            parsed = urllib.parse.urlsplit(target)
            if not parsed.hostname:
                client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                return
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            headers = []
            for line in lines[1:]:
                lower = line.lower()
                if lower.startswith(("proxy-connection:", "proxy-authorization:", "connection:")):
                    continue
                headers.append(line)
            request = f"{method} {path} {version}\r\n" + "\r\n".join(headers) + "\r\nConnection: close\r\n\r\n"
            upstream = self.create_connection(node_id, (parsed.hostname, port))
            upstream.sendall(request.encode("iso-8859-1") + rest)
            relay(client, upstream)
        except Exception as exc:
            print(f"[ClashBridge] HTTP client {address} failed: {exc}", flush=True)
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
        finally:
            client.close()
            if upstream:
                upstream.close()

    def _authenticate_http(self, lines: list[str]) -> dict[str, Any] | None:
        for line in lines[1:]:
            if not line.lower().startswith("proxy-authorization:"):
                continue
            value = line.split(":", 1)[1].strip()
            scheme, _sep, encoded = value.partition(" ")
            if scheme.lower() != "basic" or not encoded:
                return None
            try:
                raw = base64.b64decode(encoded).decode("utf-8", errors="replace")
            except Exception:
                return None
            username, sep, password = raw.partition(":")
            if not sep:
                return None
            return self._authenticate(username, password)
        return None
