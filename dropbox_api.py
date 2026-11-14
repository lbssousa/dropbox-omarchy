"""Account space usage from the Dropbox HTTP API.

The desktop client keeps the account quota only in its encrypted config, so the
real allocation has to come from `users/get_space_usage`. That needs an OAuth
token from a Dropbox app the user registers (Scoped access, `account_info.read`,
redirect URI REDIRECT_URI). Authorization uses PKCE, so only the app key is
needed — no app secret. The long-lived refresh token goes to the Secret Service
keyring through `secret-tool` (or a 0600 file when it is missing); the
short-lived access token and the last reading are cached on disk.
"""

import base64
import hashlib
import http.server
import json
import os
import secrets
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


PLUGIN_ID = "lbssousa.dropbox"
REDIRECT_PORT = 47823
REDIRECT_URI = f"http://localhost:{REDIRECT_PORT}/"
AUTHORIZE_URL = "https://www.dropbox.com/oauth2/authorize"
TOKEN_URL = "https://api.dropboxapi.com/oauth2/token"
SPACE_URL = "https://api.dropboxapi.com/2/users/get_space_usage"
SPACE_TTL_SEC = 600
HTTP_TIMEOUT_SEC = 8
AUTHORIZE_TIMEOUT_SEC = 300


class ApiError(Exception):
  pass


class NotConnected(ApiError):
  pass


def _xdg(name, fallback):
  value = os.environ.get(name)
  return Path(value) if value else Path.home() / fallback


def state_dir():
  return _xdg("XDG_STATE_HOME", ".local/state") / PLUGIN_ID


def cache_dir():
  return _xdg("XDG_CACHE_HOME", ".cache") / PLUGIN_ID


def _read_json(path):
  try:
    with path.open("r", encoding="utf-8") as handle:
      data = json.load(handle)
    return data if isinstance(data, dict) else {}
  except (OSError, json.JSONDecodeError):
    return {}


def _write_private(path, text):
  path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
  tmp = path.with_name(path.name + ".tmp")
  fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
  with os.fdopen(fd, "w", encoding="utf-8") as handle:
    handle.write(text)
  os.replace(tmp, path)


def _remove(path):
  try:
    path.unlink()
  except OSError:
    pass


# --- Refresh token storage -------------------------------------------------

SECRET_ATTRS = ["application", PLUGIN_ID, "kind", "refresh_token"]


def _token_file():
  return state_dir() / "refresh_token"


def load_refresh_token():
  if shutil.which("secret-tool"):
    try:
      done = subprocess.run(["secret-tool", "lookup", *SECRET_ATTRS], capture_output=True, text=True, timeout=5)
      if done.returncode == 0 and done.stdout.strip():
        return done.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
      pass
  try:
    return _token_file().read_text(encoding="utf-8").strip()
  except OSError:
    return ""


def store_refresh_token(token):
  if shutil.which("secret-tool"):
    try:
      done = subprocess.run(
        ["secret-tool", "store", "--label=Dropbox quota (Omarchy bar)", *SECRET_ATTRS],
        input=token, capture_output=True, text=True, timeout=30,
      )
      if done.returncode == 0:
        _remove(_token_file())
        return
    except (OSError, subprocess.TimeoutExpired):
      pass
  _write_private(_token_file(), token)


def clear_tokens():
  if shutil.which("secret-tool"):
    try:
      subprocess.run(["secret-tool", "clear", *SECRET_ATTRS], capture_output=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
      pass
  _remove(_token_file())
  _remove(state_dir() / "access_token.json")
  _remove(cache_dir() / "space.json")


# --- HTTP ------------------------------------------------------------------

def _post(url, data, headers=None):
  request = urllib.request.Request(url, data=data, headers=headers or {}, method="POST")
  try:
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SEC) as response:
      return json.loads(response.read().decode("utf-8") or "null")
  except urllib.error.HTTPError as error:
    body = error.read().decode("utf-8", "replace")
    try:
      detail = json.loads(body)
      summary = detail.get("error_summary") or detail.get("error_description") or detail.get("error") or body
    except json.JSONDecodeError:
      summary = body
    raise ApiError(f"HTTP {error.code}: {str(summary).strip()[:160]}") from None
  except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as error:
    raise ApiError(f"network error: {getattr(error, 'reason', error)}") from None
  except json.JSONDecodeError:
    raise ApiError("invalid response from Dropbox") from None


def _token_request(fields):
  return _post(TOKEN_URL, urllib.parse.urlencode(fields).encode("ascii"),
               {"Content-Type": "application/x-www-form-urlencoded"})


def access_token(app_key):
  cached_path = state_dir() / "access_token.json"
  cached = _read_json(cached_path)
  if cached.get("appKey") == app_key and cached.get("token") and cached.get("expiresAt", 0) > time.time() + 60:
    return cached["token"]

  refresh = load_refresh_token()
  if not refresh:
    raise NotConnected("not connected")
  try:
    reply = _token_request({"grant_type": "refresh_token", "refresh_token": refresh, "client_id": app_key})
  except ApiError as error:
    if "invalid_grant" in str(error):
      clear_tokens()
      raise NotConnected("authorization revoked — connect again") from None
    raise
  token = reply.get("access_token") if isinstance(reply, dict) else None
  if not token:
    raise ApiError("no access token in Dropbox reply")
  expires_at = time.time() + int(reply.get("expires_in") or 3600)
  _write_private(cached_path, json.dumps({"appKey": app_key, "token": token, "expiresAt": expires_at}))
  return token


def parse_space_usage(reply):
  """(used, allocated) from a get_space_usage reply; allocated 0 when unknown."""
  if not isinstance(reply, dict):
    raise ApiError("invalid space usage reply")
  used = int(reply.get("used") or 0)
  allocation = reply.get("allocation") or {}
  tag = allocation.get(".tag")
  allocated = 0
  if tag == "individual":
    allocated = int(allocation.get("allocated") or 0)
  elif tag == "team":
    # A per-member cap, when the team sets one, is the limit that applies.
    allocated = int(allocation.get("user_within_team_space_allocated") or 0) or int(allocation.get("allocated") or 0)
  return used, allocated


def space_usage(app_key, max_age=SPACE_TTL_SEC):
  """{"used", "allocated", "fetchedAt", "stale", "error"} or raises NotConnected.

  A failed fetch falls back to the last good reading, marked stale.
  """
  cache_path = cache_dir() / "space.json"
  cached = _read_json(cache_path)
  if cached.get("appKey") != app_key:
    cached = {}
  if cached and time.time() - float(cached.get("fetchedAt", 0)) < max_age:
    return {**cached, "stale": False, "error": ""}

  try:
    token = access_token(app_key)
    reply = _post(SPACE_URL, b"null", {"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    used, allocated = parse_space_usage(reply)
  except NotConnected:
    raise
  except ApiError as error:
    if cached:
      return {**cached, "stale": True, "error": str(error)}
    raise

  reading = {"appKey": app_key, "used": used, "allocated": allocated, "fetchedAt": time.time()}
  _write_private(cache_path, json.dumps(reading))
  return {**reading, "stale": False, "error": ""}


# --- Authorization (PKCE + loopback redirect) --------------------------------

def _pkce_pair():
  verifier = secrets.token_urlsafe(64)[:96]
  challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
  return verifier, challenge


def authorize(app_key, emit=print):
  """Run the browser authorization flow, then store the refresh token.

  Prints the authorize URL (the panel opens the first URL it sees) and waits
  for Dropbox to redirect back to the loopback server.
  """
  verifier, challenge = _pkce_pair()
  state = secrets.token_urlsafe(24)
  result = {}
  done = threading.Event()

  class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
      query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
      if query.get("state", [""])[0] != state:
        self.send_response(400)
        self.end_headers()
        return
      result["code"] = query.get("code", [""])[0]
      result["error"] = query.get("error_description", query.get("error", [""]))[0]
      ok = bool(result["code"])
      self.send_response(200)
      self.send_header("Content-Type", "text/html; charset=utf-8")
      self.end_headers()
      message = "Dropbox connected. You can close this tab." if ok else "Dropbox authorization failed: " + result["error"]
      self.wfile.write(f"<!doctype html><meta charset=utf-8><title>Dropbox</title><p>{message}</p>".encode("utf-8"))
      done.set()

    def log_message(self, *args):
      pass

  class Server6(http.server.HTTPServer):
    address_family = socket.AF_INET6

  servers = []
  for cls, host in ((http.server.HTTPServer, "127.0.0.1"), (Server6, "::1")):
    try:
      servers.append(cls((host, REDIRECT_PORT), Handler))
    except OSError:
      pass
  if not servers:
    raise ApiError(f"port {REDIRECT_PORT} is busy")
  for server in servers:
    threading.Thread(target=server.serve_forever, daemon=True).start()

  try:
    url = AUTHORIZE_URL + "?" + urllib.parse.urlencode({
      "client_id": app_key,
      "response_type": "code",
      "redirect_uri": REDIRECT_URI,
      "code_challenge": challenge,
      "code_challenge_method": "S256",
      "token_access_type": "offline",
      "scope": "account_info.read",
      "state": state,
    })
    emit(url)
    if not done.wait(AUTHORIZE_TIMEOUT_SEC):
      raise ApiError("timed out waiting for Dropbox authorization")
  finally:
    for server in servers:
      server.shutdown()
      server.server_close()

  if not result.get("code"):
    raise ApiError("authorization denied: " + (result.get("error") or "no code"))

  reply = _token_request({
    "grant_type": "authorization_code",
    "code": result["code"],
    "client_id": app_key,
    "code_verifier": verifier,
    "redirect_uri": REDIRECT_URI,
  })
  refresh = reply.get("refresh_token") if isinstance(reply, dict) else None
  if not refresh:
    raise ApiError("no refresh token in Dropbox reply")
  clear_tokens()
  store_refresh_token(refresh)
  if reply.get("access_token"):
    _write_private(state_dir() / "access_token.json", json.dumps({
      "appKey": app_key,
      "token": reply["access_token"],
      "expiresAt": time.time() + int(reply.get("expires_in") or 3600),
    }))
