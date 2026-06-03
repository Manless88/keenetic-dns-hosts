import unittest
import json
import os
from urllib.error import HTTPError

import server


class RouterHostsParserTest(unittest.TestCase):
    def test_enrich_hosts_combines_router_and_panel_records(self):
        original_read_router = server.read_router_host_records
        original_read_json = server.read_json
        try:
            server.read_router_host_records = lambda user="", password="": [{"hostname": "example-router.local", "ip": "198.51.100.4"}]

            def fake_read_json(path, fallback):
                if path == server.HOSTS_FILE:
                    return [
                        {
                            "hostname": "example-plug.local",
                            "mode": "manual",
                            "ip": "192.0.2.132",
                            "mac": "",
                            "lastIp": "192.0.2.132",
                        },
                        {
                            "hostname": "example-router.local",
                            "mode": "manual",
                            "ip": "198.51.100.4",
                            "mac": "",
                            "lastIp": "198.51.100.4",
                        },
                    ]
                return []

            server.read_json = fake_read_json

            records = server.enrich_hosts()

            self.assertEqual([item["hostname"] for item in records], ["example-router.local", "example-plug.local"])
            self.assertTrue(records[0]["editable"])
            self.assertEqual(records[0]["source"], "app")
            self.assertTrue(records[1]["editable"])
            self.assertEqual(records[1]["source"], "app")
        finally:
            server.read_router_host_records = original_read_router
            server.read_json = original_read_json

    def test_router_only_hosts_are_editable(self):
        original_read_router = server.read_router_host_records
        original_read_json = server.read_json
        try:
            server.read_router_host_records = lambda user="", password="": [{"hostname": "router-only.local", "ip": "192.0.2.55"}]
            server.read_json = lambda path, fallback: []

            records = server.enrich_hosts()

            self.assertEqual(records[0]["source"], "router")
            self.assertTrue(records[0]["editable"])
        finally:
            server.read_router_host_records = original_read_router
            server.read_json = original_read_json

    def test_read_router_host_records_uses_rci_ip_host_endpoint(self):
        original_rci_get = server.rci_get
        try:
            server.rci_get = lambda path: [
                {"domain": "service-dnscheck.test", "address": "192.0.2.1"},
                {"domain": "example-router.local", "address": "198.51.100.4"},
                {"domain": "example-plug.local", "address": "192.0.2.132"},
            ]

            records = server.read_router_host_records()

            self.assertEqual(
                records,
                [
                    {"hostname": "example-router.local", "ip": "198.51.100.4"},
                    {"hostname": "example-plug.local", "ip": "192.0.2.132"},
                ],
            )
        finally:
            server.rci_get = original_rci_get

    def test_refresh_clients_uses_rci_hotspot_endpoint(self):
        original_rci_get = server.rci_get
        original_write_json = server.write_json
        written = []
        try:
            server.rci_get = lambda path: {
                "host": [
                    {
                        "ip": "192.0.2.74",
                        "mac": "02:00:00:00:00:01",
                        "name": "ExampleNAS",
                        "hostname": "example-nas",
                        "active": "yes",
                        "registered": "yes",
                    },
                    {
                        "ip": "192.0.2.90",
                        "mac": "02:00:00:00:00:02",
                        "name": "Guest",
                        "active": "yes",
                        "registered": "no",
                    },
                ]
            }
            server.write_json = lambda path, value: written.append((path, value))

            clients = server.refresh_clients_from_router()

            self.assertEqual(len(clients), 1)
            self.assertEqual(clients[0]["name"], "ExampleNAS")
            self.assertEqual(clients[0]["hostname"], "example-nas")
            self.assertEqual(written[0][0], server.CLIENTS_FILE)
        finally:
            server.rci_get = original_rci_get
            server.write_json = original_write_json

    def test_clients_for_panel_reads_router_first(self):
        original_refresh = server.refresh_clients_from_router
        try:
            server.refresh_clients_from_router = lambda user="", password="": [{"name": "ExampleNAS", "ip": "192.0.2.74"}]

            clients, source, warning = server.clients_for_panel()

            self.assertEqual(clients, [{"name": "ExampleNAS", "ip": "192.0.2.74"}])
            self.assertEqual(source, "router")
            self.assertEqual(warning, "")
        finally:
            server.refresh_clients_from_router = original_refresh

    def test_clients_for_panel_falls_back_to_cache(self):
        original_refresh = server.refresh_clients_from_router
        original_read_json = server.read_json
        try:
            server.refresh_clients_from_router = lambda user="", password="": (_ for _ in ()).throw(RuntimeError("router down"))
            server.read_json = lambda path, fallback: [{"name": "Cached", "ip": "192.0.2.10"}]

            clients, source, warning = server.clients_for_panel()

            self.assertEqual(clients, [{"name": "Cached", "ip": "192.0.2.10"}])
            self.assertEqual(source, "cache")
            self.assertIn("router down", warning)
        finally:
            server.refresh_clients_from_router = original_refresh
            server.read_json = original_read_json

    def test_write_router_host_uses_rci_ip_host_and_saves_config(self):
        original_rci_post = server.rci_post
        calls = []
        try:
            server.rci_post = lambda payload: calls.append(payload)

            server.write_router_host({"hostname": "example-plug.local", "mode": "manual", "ip": "192.0.2.132"})

            self.assertEqual(
                calls,
                [
                    {"ip": {"host": {"domain": "example-plug.local", "address": "192.0.2.132"}}},
                    {"system": {"configuration": {"save": {}}}},
                ],
            )
        finally:
            server.rci_post = original_rci_post

    def test_delete_router_host_uses_rci_no_ip_host_and_saves_config(self):
        original_rci_post = server.rci_post
        calls = []
        try:
            server.rci_post = lambda payload: calls.append(payload)

            server.delete_router_host({"hostname": "example-plug.local", "mode": "manual", "lastIp": "192.0.2.132"})

            self.assertEqual(
                calls,
                [
                    {"ip": {"host": {"domain": "example-plug.local", "address": "192.0.2.132", "no": True}}},
                    {"system": {"configuration": {"save": {}}}},
                ],
            )
        finally:
            server.rci_post = original_rci_post

    def test_router_host_by_name_returns_current_router_record(self):
        original_read_router = server.read_router_host_records
        try:
            server.read_router_host_records = lambda user="", password="": [
                {"hostname": "old.local", "ip": "192.0.2.10"},
                {"hostname": "router-only.local", "ip": "192.0.2.55"},
            ]

            self.assertEqual(
                server.router_host_by_name("router-only.local"),
                {"hostname": "router-only.local", "ip": "192.0.2.55"},
            )
            self.assertIsNone(server.router_host_by_name("missing.local"))
        finally:
            server.read_router_host_records = original_read_router

    def test_router_login_uses_keenetic_http_auth_challenge(self):
        original_urlopen = server.urlopen
        requests = []

        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b"{}"

        def fake_urlopen(request, timeout=0):
            requests.append(request)
            if len(requests) == 1:
                error = HTTPError(request.full_url, 401, "Unauthorized", None, None)
                error.headers = {
                    "X-NDM-Challenge": "challenge",
                    "X-NDM-Realm": "Keenetic",
                    "Set-Cookie": "sysauth=abc; Path=/",
                }
                raise error
            return FakeResponse()

        try:
            server.urlopen = fake_urlopen

            server.authenticate_router_user("keenetic", "secret")

            self.assertEqual(requests[0].full_url, "http://192.168.1.1/auth")
            self.assertEqual(requests[1].full_url, "http://192.168.1.1/auth")
            body = json.loads(requests[1].data.decode("utf-8"))
            self.assertEqual(body["login"], "keenetic")
            self.assertNotEqual(body["password"], "secret")
            self.assertEqual(requests[1].get_header("Cookie"), "sysauth=abc")
        finally:
            server.urlopen = original_urlopen

    def test_router_login_rejects_invalid_keenetic_credentials(self):
        original_urlopen = server.urlopen

        def fake_urlopen(request, timeout=0):
            error = HTTPError(request.full_url, 401, "Unauthorized", None, None)
            error.headers = {}
            raise error

        try:
            server.urlopen = fake_urlopen
            with self.assertRaises(RuntimeError):
                server.authenticate_router_user("keenetic", "bad-password")
        finally:
            server.urlopen = original_urlopen

    def test_sync_client_hosts_updates_router_when_client_ip_changes(self):
        original_read_json = server.read_json
        original_write_json = server.write_json
        original_refresh_clients = server.refresh_clients_from_router
        original_read_router = server.read_router_host_records
        original_write_router = server.write_router_host
        original_delete_router = server.delete_router_host
        writes = []
        deleted = []
        written_hosts = []
        try:
            stored_hosts = [
                {
                    "hostname": "example-nas.local",
                    "mode": "client",
                    "ip": "",
                    "mac": "02:00:00:00:00:01",
                    "lastIp": "192.0.2.74",
                }
            ]
            clients = [
                {
                    "name": "ExampleNAS",
                    "ip": "192.0.2.91",
                    "mac": "02:00:00:00:00:01",
                }
            ]

            def fake_read_json(path, fallback):
                if path == server.HOSTS_FILE:
                    return [dict(item) for item in stored_hosts]
                if path == server.CLIENTS_FILE:
                    return [dict(item) for item in clients]
                return fallback

            server.read_json = fake_read_json
            server.write_json = lambda path, value: writes.append((path, value))
            server.refresh_clients_from_router = lambda: clients
            server.read_router_host_records = lambda user="", password="": [
                {"hostname": "example-nas.local", "ip": "192.0.2.74"}
            ]
            server.delete_router_host = lambda host: deleted.append(dict(host))
            server.write_router_host = lambda host: written_hosts.append(dict(host))

            result = server.sync_client_hosts_once()

            self.assertEqual(result["updated"], 1)
            self.assertEqual(deleted[0]["lastIp"], "192.0.2.74")
            self.assertEqual(written_hosts[0]["lastIp"], "192.0.2.91")
            self.assertEqual(writes[0][0], server.HOSTS_FILE)
            self.assertEqual(writes[0][1][0]["lastIp"], "192.0.2.91")
        finally:
            server.read_json = original_read_json
            server.write_json = original_write_json
            server.refresh_clients_from_router = original_refresh_clients
            server.read_router_host_records = original_read_router
            server.write_router_host = original_write_router
            server.delete_router_host = original_delete_router

    def test_service_status_reports_current_process_when_init_script_is_absent(self):
        status = server.service_status()

        self.assertEqual(status["state"], "running")
        self.assertEqual(status["pid"], os.getpid())
        self.assertTrue(status["controlAvailable"])
        self.assertIn(status["syncControl"], {"running", "stopped"})
        self.assertEqual(status["version"], server.app_version())

    def test_service_control_manages_sync_without_stopping_web_service(self):
        original_enabled = server.SYNC_CONTROL["enabled"]
        original_thread = server.SYNC_CONTROL["thread"]
        original_start_sync_thread = server.start_sync_thread
        started = []
        class FakeThread:
            def is_alive(self):
                return True

        def fake_start_sync_thread():
            started.append(True)
            server.SYNC_CONTROL["enabled"] = True
            server.SYNC_CONTROL["thread"] = FakeThread()

        try:
            server.SYNC_CONTROL["enabled"] = False
            server.SYNC_CONTROL["thread"] = None
            server.start_sync_thread = fake_start_sync_thread

            stopped = server.service_control("stop")
            self.assertEqual(stopped["state"], "running")
            self.assertEqual(stopped["syncControl"], "stopped")

            started_status = server.service_control("start")
            self.assertEqual(started_status["state"], "running")
            self.assertEqual(started_status["syncControl"], "running")
            self.assertEqual(started, [True])
        finally:
            server.SYNC_CONTROL["enabled"] = original_enabled
            server.SYNC_CONTROL["thread"] = original_thread
            server.start_sync_thread = original_start_sync_thread


if __name__ == "__main__":
    unittest.main()
