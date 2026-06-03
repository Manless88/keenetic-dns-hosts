from __future__ import annotations

import json
import re
import os
import socket
import secrets
import hashlib
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent
WEB_DIR = ROOT / "web"
VERSION_FILE = ROOT / "VERSION"


def read_config_file(path: Path):
    values = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        values[key.strip()] = value
    return values


def app_version() -> str:
    if not VERSION_FILE.exists():
        return "dev"
    return VERSION_FILE.read_text(encoding="utf-8").strip() or "dev"


CONFIG_FILE = Path(
    os.environ.get(
        "KEENETIC_DNS_HOSTS_CONFIG",
        os.environ.get("DNS_HOSTS_WEB_CONFIG", "/opt/etc/keenetic-dns-hosts.conf"),
    )
)
CONFIG = read_config_file(CONFIG_FILE)


def setting(name: str, default: str) -> str:
    return os.environ.get(name, CONFIG.get(name, default))


DATA_DIR = Path(setting("DATA_DIR", str(ROOT / "data")))
CLIENTS_FILE = DATA_DIR / "clients.json"
HOSTS_FILE = DATA_DIR / "hosts.json"
ROUTER_HOST = setting("ROUTER_HOST", "192.168.1.1")
RCI_URL = setting("RCI_URL", "http://localhost:79/rci")
APP_HOST = setting("APP_HOST", "0.0.0.0")
APP_PORT = int(setting("APP_PORT", "3333"))
SYNC_INTERVAL = int(setting("SYNC_INTERVAL", "30"))
AUTO_SYNC = setting("AUTO_SYNC", "1").strip().lower() not in {"0", "false", "no"}
SESSIONS = {}
SYNC_STATE = {
    "running": False,
    "lastRun": "",
    "lastError": "",
    "lastResult": {},
}
SYNC_CONTROL = {
    "enabled": AUTO_SYNC,
    "thread": None,
}
SYNC_LOCK = threading.Lock()


HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
DNS_LABEL_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
IPV4_RE = re.compile(r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$")
MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


def read_json(path: Path, fallback):
    if not path.exists():
        return fallback
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def raw_http_request(url: str, payload=None, headers=None, timeout=10):
    body = None
    request_headers = dict(headers or {})
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = Request(url, data=body, headers=request_headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except HTTPError as exc:
        raise exc
    except URLError as exc:
        raise RuntimeError(f"не удалось подключиться к Keenetic: {exc.reason}") from exc
    return raw


def json_request(url: str, payload=None, headers=None, timeout=10):
    raw = raw_http_request(url, payload, headers, timeout)
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def router_http_base() -> str:
    value = ROUTER_HOST.strip().rstrip("/")
    if value.startswith(("http://", "https://")):
        return value
    return f"http://{value}"


def auth_cookie_header(headers) -> str:
    cookies = []
    if hasattr(headers, "get_all"):
        values = headers.get_all("Set-Cookie") or []
    else:
        value = headers.get("Set-Cookie", "")
        values = [value] if value else []
    for value in values:
        cookie = SimpleCookie(value)
        for morsel in cookie.values():
            cookies.append(f"{morsel.key}={morsel.value}")
    return "; ".join(cookies)


def keenetic_password_hash(user: str, password: str, realm: str, challenge: str) -> str:
    first = hashlib.md5(f"{user}:{realm}:{password}".encode("utf-8")).hexdigest()
    return hashlib.sha256(f"{challenge}{first}".encode("utf-8")).hexdigest()


def authenticate_router_user(user: str, password: str) -> None:
    if not user or not password:
        raise RuntimeError("укажите логин и пароль Keenetic")
    auth_url = f"{router_http_base()}/auth"
    try:
        raw_http_request(auth_url, timeout=10)
        return
    except HTTPError as exc:
        if exc.code != HTTPStatus.UNAUTHORIZED:
            raise RuntimeError(f"Keenetic вернул HTTP {exc.code}") from exc
        challenge = (exc.headers.get("X-NDM-Challenge") or "").strip()
        realm = (exc.headers.get("X-NDM-Realm") or "").strip()
        if not challenge or not realm:
            raise RuntimeError("Keenetic не вернул challenge для авторизации") from exc
        cookie_header = auth_cookie_header(exc.headers)

    headers = {}
    if cookie_header:
        headers["Cookie"] = cookie_header
    payload = {
        "login": user,
        "password": keenetic_password_hash(user, password, realm, challenge),
    }
    try:
        raw_http_request(auth_url, payload, headers=headers, timeout=10)
    except HTTPError as exc:
        if exc.code == HTTPStatus.UNAUTHORIZED:
            raise RuntimeError("неверный логин или пароль Keenetic") from exc
        raise RuntimeError(f"Keenetic вернул HTTP {exc.code}") from exc


def rci_url(path: str = "") -> str:
    base = RCI_URL.rstrip("/")
    if not path:
        return f"{base}/"
    return f"{base}/{path.lstrip('/')}"


def rci_get(path: str):
    return json_request(rci_url(path), timeout=30)


def rci_post(payload):
    try:
        return json_request(rci_url(), payload, timeout=30)
    except HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"RCI вернул HTTP {exc.code}: {body}") from exc


def truthy_router_value(value, default=False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"yes", "true", "1"}


def parse_rci_hotspot_clients(payload):
    clients = []
    seen = set()
    hosts = payload.get("host", []) if isinstance(payload, dict) else []
    for item in hosts:
        mac = str(item.get("mac", "")).strip().lower()
        ip = str(item.get("ip", "")).strip()
        if not mac or not ip or ip == "0.0.0.0" or mac in seen:
            continue
        if not truthy_router_value(item.get("registered"), default=True):
            continue
        seen.add(mac)
        name = str(item.get("name", "")).strip() or mac
        hostname = str(item.get("hostname", "")).strip()
        if hostname.startswith("name:") or not HOSTNAME_RE.match(hostname):
            hostname = ""
        clients.append(
            {
                "ip": ip,
                "mac": mac,
                "name": name,
                "hostname": hostname,
                "registered": True,
                "active": truthy_router_value(item.get("active"), default=False),
                "interface": str(item.get("link", "") or item.get("interface", "")),
            }
        )
    clients.sort(key=lambda item: (not item["active"], item["name"].lower()))
    return clients


def detect_reverse_hostname(ip: str) -> str:
    if not ip or ip == "0.0.0.0":
        return ""
    previous_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2)
        name = socket.gethostbyaddr(ip)[0].rstrip(".")
    except (OSError, socket.herror, socket.gaierror, TimeoutError):
        return ""
    finally:
        socket.setdefaulttimeout(previous_timeout)
    return name if HOSTNAME_RE.match(name) else ""


def enrich_client_hostnames(clients):
    for client in clients:
        if client.get("hostname"):
            client["hostnameSource"] = "router"
            continue
        if not client.get("active"):
            client["hostnameSource"] = ""
            continue
        detected = detect_reverse_hostname(client.get("ip", ""))
        if detected:
            client["hostname"] = detected
            client["hostnameSource"] = "reverse-dns"
        elif DNS_LABEL_RE.match(client.get("name", "")):
            client["hostname"] = f"{client['name'].lower()}.local"
            client["hostnameSource"] = "name-fallback"
        else:
            client["hostnameSource"] = ""
    return clients


def refresh_clients_from_router(user: str = "", password: str = ""):
    clients = enrich_client_hostnames(parse_rci_hotspot_clients(rci_get("/show/ip/hotspot")))
    if not clients:
        raise RuntimeError("роутер не вернул зарегистрированных клиентов")
    write_json(CLIENTS_FILE, clients)
    return clients


def clients_for_panel(user: str = "", password: str = ""):
    try:
        return refresh_clients_from_router(user, password), "router", ""
    except Exception as exc:
        return read_json(CLIENTS_FILE, []), "cache", str(exc)


def parse_rci_host_records(payload):
    records = []
    entries = payload if isinstance(payload, list) else payload.get("host", []) if isinstance(payload, dict) else []
    for item in entries:
        hostname = str(item.get("domain", "") or item.get("hostname", "")).strip().lower()
        ip = str(item.get("address", "") or item.get("ip", "")).strip()
        if not hostname or not IPV4_RE.match(ip):
            continue
        if hostname.endswith("-dnscheck.test"):
            continue
        records.append({"hostname": hostname, "ip": ip})
    return records


def read_router_host_records(user: str = "", password: str = ""):
    return parse_rci_host_records(rci_get("/show/rc/ip/host"))


def clients_by_mac():
    clients = read_json(CLIENTS_FILE, [])
    return {client.get("mac", "").lower(): client for client in clients if client.get("mac")}


def resolved_ip(host):
    if host.get("mode") == "client":
        client = clients_by_mac().get(host.get("mac", "").lower())
        return client.get("ip", "") if client else ""
    return host.get("ip", "")


def host_status(host):
    current_ip = resolved_ip(host)
    if not current_ip:
        return "missing-client"
    if host.get("lastIp") and host.get("lastIp") != current_ip:
        return "ip-changed"
    return "in-sync"


def host_view(host, current_ip=None, client=None, source="app", editable=True):
    clients = clients_by_mac()
    if client is None and host.get("mode") == "client":
        client = clients.get(host.get("mac", "").lower())
    if current_ip is None:
        current_ip = client.get("ip", "") if host.get("mode") == "client" and client else resolved_ip(host)
    status = "missing-client" if not current_ip else "in-sync"
    if host.get("lastIp") and host.get("lastIp") != current_ip:
        status = "ip-changed"
    return {
        "hostname": host.get("hostname", ""),
        "mode": host.get("mode", "manual"),
        "ip": host.get("ip", ""),
        "mac": host.get("mac", ""),
        "lastIp": host.get("lastIp", ""),
        "currentIp": current_ip,
        "status": status,
        "clientName": client.get("name", "") if client else "",
        "source": source,
        "editable": editable,
    }


def enrich_stored_hosts(stored_hosts, skip_hostnames=None):
    result = []
    skip_hostnames = skip_hostnames or set()
    for host in stored_hosts:
        hostname = host.get("hostname", "")
        if hostname in skip_hostnames:
            continue
        result.append(host_view(host, source="app", editable=True))
    return result


def enrich_hosts(user: str = "", password: str = ""):
    result = []
    stored_hosts = read_json(HOSTS_FILE, [])
    stored_by_hostname = {host.get("hostname", ""): host for host in stored_hosts}
    router_names = set()
    for record in read_router_host_records(user, password):
        router_names.add(record["hostname"])
        stored = stored_by_hostname.get(record["hostname"])
        if stored:
            result.append(host_view(stored, current_ip=record["ip"], source="app", editable=True))
            continue
        result.append(
            {
                "hostname": record["hostname"],
                "mode": "manual",
                "ip": record["ip"],
                "mac": "",
                "lastIp": record["ip"],
                "currentIp": record["ip"],
                "status": "in-sync",
                "clientName": "",
                "source": "router",
                "editable": True,
            }
        )
    return result + enrich_stored_hosts(stored_hosts, router_names)


def validate_host(payload):
    hostname = str(payload.get("hostname", "")).strip().lower()
    mode = str(payload.get("mode", "manual")).strip()
    ip = str(payload.get("ip", "")).strip()
    mac = str(payload.get("mac", "")).strip().lower()

    if not HOSTNAME_RE.match(hostname):
        return None, "Hostname должен быть корректным DNS-именем."
    if mode not in {"manual", "client"}:
        return None, "Тип привязки должен быть: вручную или клиент."
    if mode == "manual" and not IPV4_RE.match(ip):
        return None, "Для ручной привязки нужен корректный IPv4-адрес."
    if mode == "client" and not MAC_RE.match(mac):
        return None, "Для привязки к клиенту нужен корректный MAC-адрес."

    current_ip = ip
    if mode == "client":
        client = clients_by_mac().get(mac)
        current_ip = client.get("ip", "") if client else ""

    return {
        "hostname": hostname,
        "mode": mode,
        "ip": ip if mode == "manual" else "",
        "mac": mac if mode == "client" else "",
        "lastIp": current_ip,
    }, ""


def require_host_ip(host):
    ip = resolved_ip(host)
    if not ip:
        raise RuntimeError("у алиаса нет актуального IP-адреса")
    return ip


def write_router_host(host, user: str = "", password: str = ""):
    ip = require_host_ip(host)
    rci_post({"ip": {"host": {"domain": host["hostname"], "address": ip}}})
    rci_post({"system": {"configuration": {"save": {}}}})


def delete_router_host(host, user: str = "", password: str = ""):
    ip = host.get("lastIp") or host.get("ip") or resolved_ip(host)
    if not ip:
        raise RuntimeError("не удалось определить IP-адрес для удаления алиаса")
    rci_post({"ip": {"host": {"domain": host["hostname"], "address": ip, "no": True}}})
    rci_post({"system": {"configuration": {"save": {}}}})


def router_host_by_name(hostname: str, user: str = "", password: str = ""):
    for record in read_router_host_records(user, password):
        if record["hostname"] == hostname:
            return record
    return None


def iso_now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def sync_client_hosts_once():
    clients = refresh_clients_from_router()
    clients_by_current_mac = {client.get("mac", "").lower(): client for client in clients if client.get("mac")}
    hosts = read_json(HOSTS_FILE, [])
    router_records = {record["hostname"]: record for record in read_router_host_records()}
    updated = 0
    missing = 0
    skipped = 0
    changed = False

    for host in hosts:
        if host.get("mode") != "client":
            skipped += 1
            continue
        client = clients_by_current_mac.get(host.get("mac", "").lower())
        current_ip = client.get("ip", "") if client else ""
        if not current_ip:
            missing += 1
            continue

        hostname = host.get("hostname", "")
        router_record = router_records.get(hostname)
        router_ip = router_record.get("ip", "") if router_record else ""
        if router_ip == current_ip and host.get("lastIp") == current_ip:
            continue

        previous_ip = router_ip or host.get("lastIp", "")
        if previous_ip and previous_ip != current_ip:
            delete_router_host({**host, "lastIp": previous_ip})
        write_router_host({**host, "lastIp": current_ip})
        host["lastIp"] = current_ip
        updated += 1
        changed = True

    if changed:
        write_json(HOSTS_FILE, hosts)

    return {
        "checked": len(hosts),
        "updated": updated,
        "missing": missing,
        "skipped": skipped,
    }


def sync_client_hosts_safely():
    with SYNC_LOCK:
        SYNC_STATE["running"] = True
        try:
            result = sync_client_hosts_once()
            SYNC_STATE["lastResult"] = result
            SYNC_STATE["lastError"] = ""
            return result
        except Exception as exc:
            SYNC_STATE["lastError"] = str(exc)
            raise
        finally:
            SYNC_STATE["lastRun"] = iso_now()
            SYNC_STATE["running"] = False


def sync_loop():
    while SYNC_CONTROL["enabled"]:
        try:
            sync_client_hosts_safely()
        except Exception:
            pass
        for _ in range(max(SYNC_INTERVAL, 5)):
            if not SYNC_CONTROL["enabled"]:
                break
            time.sleep(1)
    if threading.current_thread() is SYNC_CONTROL.get("thread"):
        SYNC_CONTROL["thread"] = None


def start_sync_thread():
    SYNC_CONTROL["enabled"] = True
    thread = SYNC_CONTROL.get("thread")
    if thread and thread.is_alive():
        return
    thread = threading.Thread(target=sync_loop, daemon=True)
    SYNC_CONTROL["thread"] = thread
    thread.start()


def stop_sync_thread():
    SYNC_CONTROL["enabled"] = False


def sync_control_state() -> str:
    thread = SYNC_CONTROL.get("thread")
    if SYNC_CONTROL["enabled"] and thread and thread.is_alive():
        return "running"
    return "stopped"


def service_status():
    return {
        "state": "running",
        "pid": os.getpid(),
        "version": app_version(),
        "controlAvailable": True,
        "syncEnabled": SYNC_CONTROL["enabled"],
        "syncControl": sync_control_state(),
        "syncInterval": SYNC_INTERVAL,
        "sync": dict(SYNC_STATE),
    }


def service_control(action: str):
    if action not in {"start", "stop", "restart"}:
        raise RuntimeError("unknown service action")
    if action == "stop":
        stop_sync_thread()
    elif action == "start":
        start_sync_thread()
    elif action == "restart":
        stop_sync_thread()
        start_sync_thread()
    return service_status()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def send_json(self, body, status=HTTPStatus.OK, headers=None):
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def session_token(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get("keenetic_dns_hosts_session")
        return morsel.value if morsel else ""

    def authenticated(self):
        return self.session_token() in SESSIONS

    def router_credentials(self):
        credentials = SESSIONS.get(self.session_token())
        if not credentials:
            raise RuntimeError("нужно войти в систему")
        return credentials["user"], ""

    def do_GET(self):
        parsed = urlparse(self.path)
        rel_path = parsed.path.lstrip("/") or "index.html"
        target = (WEB_DIR / rel_path).resolve()
        if not str(target).startswith(str(WEB_DIR.resolve())) or not target.exists() or target.is_dir():
            target = WEB_DIR / "index.html"

        content = target.read_bytes()
        mime = "text/html; charset=utf-8"
        if target.suffix == ".css":
            mime = "text/css; charset=utf-8"
        elif target.suffix == ".js":
            mime = "text/javascript; charset=utf-8"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mime)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self):
        if urlparse(self.path).path != "/api":
            self.send_json({"error": "Не найдено"}, HTTPStatus.NOT_FOUND)
            return

        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self.send_json({"error": "Некорректный JSON"}, HTTPStatus.BAD_REQUEST)
            return

        cmd = payload.get("cmd")
        if cmd == "login":
            user = str(payload.get("user", ""))
            password = str(payload.get("password", ""))
            try:
                authenticate_router_user(user, password)
            except Exception:
                self.send_json({"status": 1, "error": "Неверный пользователь или пароль Keenetic"}, HTTPStatus.UNAUTHORIZED)
                return
            else:
                token = secrets.token_urlsafe(32)
                SESSIONS[token] = {"user": user}
                self.send_json(
                    {"status": 0, "auth": True},
                    headers={"Set-Cookie": f"keenetic_dns_hosts_session={token}; HttpOnly; SameSite=Lax; Path=/"},
                )
            return
        if cmd == "logout":
            token = self.session_token()
            SESSIONS.pop(token, None)
            self.send_json(
                {"status": 0, "auth": False},
                headers={"Set-Cookie": "keenetic_dns_hosts_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"},
            )
            return
        if cmd != "status" and not self.authenticated():
            self.send_json({"status": 1, "error": "Нужно войти в систему"}, HTTPStatus.UNAUTHORIZED)
            return

        if cmd == "status":
            self.send_json(
                {
                    "status": 0,
                    "name": "Keenetic DNS Hosts",
                    "version": app_version(),
                    "writeEnabled": True,
                    "routerHost": ROUTER_HOST,
                    "auth": self.authenticated(),
                }
            )
        elif cmd == "clients":
            clients, source, warning = clients_for_panel()
            self.send_json({"status": 0, "clients": clients, "source": source, "warning": warning})
        elif cmd == "refresh-clients":
            try:
                clients = refresh_clients_from_router()
                self.send_json({"status": 0, "clients": clients, "source": "router"})
            except Exception as exc:
                self.send_json(
                    {"status": 1, "error": f"Не удалось прочитать данные с роутера: {exc}"},
                    HTTPStatus.BAD_GATEWAY,
                )
        elif cmd == "hosts":
            self.send_json({"status": 0, "hosts": enrich_hosts()})
        elif cmd == "service-status":
            self.send_json({"status": 0, "daemon": service_status()})
        elif cmd == "sync-now":
            try:
                result = sync_client_hosts_safely()
                self.send_json({"status": 0, "result": result, "daemon": service_status(), "hosts": enrich_hosts()})
            except Exception as exc:
                self.send_json(
                    {"status": 1, "error": f"Не удалось синхронизировать алиасы: {exc}", "daemon": service_status()},
                    HTTPStatus.BAD_GATEWAY,
                )
        elif cmd == "service-control":
            action = str(payload.get("action", "")).strip()
            try:
                self.send_json({"status": 0, "daemon": service_control(action)})
            except Exception as exc:
                self.send_json({"status": 1, "error": str(exc), "daemon": service_status()}, HTTPStatus.BAD_GATEWAY)
        elif cmd == "add-host":
            host, error = validate_host(payload)
            if error:
                self.send_json({"status": 1, "error": error}, HTTPStatus.BAD_REQUEST)
                return
            hosts = read_json(HOSTS_FILE, [])
            existing = next((item for item in hosts if item.get("hostname") == host["hostname"]), None)
            try:
                if existing and (existing.get("lastIp") or existing.get("ip")) != require_host_ip(host):
                    delete_router_host(existing)
                write_router_host(host)
            except Exception as exc:
                self.send_json(
                    {"status": 1, "error": f"Не удалось записать алиас в Keenetic: {exc}"},
                    HTTPStatus.BAD_GATEWAY,
                )
                return
            hosts = [item for item in hosts if item.get("hostname") != host["hostname"]]
            hosts.append(host)
            write_json(HOSTS_FILE, hosts)
            self.send_json({"status": 0, "hosts": enrich_hosts()})
        elif cmd == "delete-host":
            hostname = str(payload.get("hostname", "")).strip().lower()
            hosts = read_json(HOSTS_FILE, [])
            host = next((item for item in hosts if item.get("hostname") == hostname), None)
            router_record = router_host_by_name(hostname)
            if not router_record:
                hosts = [item for item in hosts if item.get("hostname") != hostname]
                write_json(HOSTS_FILE, hosts)
                self.send_json({"status": 0, "message": "Алиас уже удален.", "hosts": enrich_hosts()})
                return
            if not host:
                host = {
                    "hostname": router_record["hostname"],
                    "mode": "manual",
                    "ip": router_record["ip"],
                    "mac": "",
                    "lastIp": router_record["ip"],
                }
            else:
                host = {**host, "lastIp": router_record["ip"]}
            try:
                delete_router_host(host)
            except Exception as exc:
                self.send_json(
                    {"status": 1, "error": f"Не удалось удалить алиас из Keenetic: {exc}"},
                    HTTPStatus.BAD_GATEWAY,
                )
                return
            hosts = [item for item in hosts if item.get("hostname") != hostname]
            write_json(HOSTS_FILE, hosts)
            self.send_json({"status": 0, "hosts": enrich_hosts()})
        else:
            self.send_json({"error": "Неизвестная команда"}, HTTPStatus.BAD_REQUEST)


def main():
    start_sync_thread()
    server = ThreadingHTTPServer((APP_HOST, APP_PORT), Handler)
    print(f"Keenetic DNS Hosts listening on http://{APP_HOST}:{APP_PORT}/")
    server.serve_forever()


if __name__ == "__main__":
    main()
