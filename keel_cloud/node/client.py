# Copyright (c) 2026 KeelLinux maintainers
"""The agent's HTTPS client: outbound only, TLS verified, the standard
library alone, so a node needs no package beyond Python and PyYAML"""

import json
import ssl
import urllib.error
import urllib.request

from keel_cloud import __version__

TIMEOUT = 30
LONG_POLL_MARGIN = 15


class CloudError(Exception):
    def __init__(self, status: int | None, message: str):
        super().__init__(message)
        self.status = status


class Client:
    def __init__(self, endpoint: str, key: str, ca_file: str | None = None,
                 opener=None):
        self.endpoint = endpoint.rstrip("/")
        self.key = key
        if opener is None:
            context = ssl.create_default_context(cafile=ca_file)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=context))
        self.opener = opener

    def call(self, method: str, path: str, body: dict | None = None,
             timeout: float = TIMEOUT) -> dict:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            self.endpoint + path, data=data, method=method,
            headers={"Authorization": f"Bearer {self.key}",
                     "Content-Type": "application/json",
                     "User-Agent": f"keel-cloud-node/{__version__}"})
        try:
            with self.opener.open(request, timeout=timeout) as response:
                return json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as failure:
            raise CloudError(failure.code, _message(failure)) from failure
        except (urllib.error.URLError, OSError, ValueError) as failure:
            reason = getattr(failure, "reason", failure)
            raise CloudError(None, f"{self.endpoint}: {reason}") from failure

    def register(self, set_name: str, record: dict, proof: str) -> dict:
        return self.call("POST", f"/v1/sets/{set_name}/peers",
                         {"record": record, "proof": proof})

    def peers(self, set_name: str, since: int = 0, wait: int = 0) -> dict:
        return self.call("GET", f"/v1/sets/{set_name}/peers?since={since}"
                         f"&wait={wait}", timeout=wait + LONG_POLL_MARGIN)

    def confirm(self, set_name: str, public_key: str) -> dict:
        return self.call("POST", f"/v1/sets/{set_name}/peers/confirm",
                         {"public_key": public_key})


def _message(failure: urllib.error.HTTPError) -> str:
    try:
        return json.loads(failure.read())["error"]
    except (ValueError, KeyError, TypeError, OSError):
        return f"HTTP {failure.code}"
