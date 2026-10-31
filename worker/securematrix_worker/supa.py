"""Minimal Supabase client (PostgREST, Storage, Auth) for the worker.

The worker uses the service-role key, so it bypasses RLS. It must never forward
that key or raw database errors to end users.
"""
from __future__ import annotations

import json
from typing import Any, Iterable

import httpx

from .config import settings


class SupabaseError(RuntimeError):
    pass


class Supa:
    def __init__(self, url: str | None = None, key: str | None = None) -> None:
        self.url = (url or settings.supabase_url).rstrip("/")
        key = key or settings.service_key
        headers = {"apikey": key}
        # Legacy JWT keys also go in the Authorization header; new sb_secret_ keys only need apikey.
        if key.startswith("eyJ"):
            headers["Authorization"] = f"Bearer {key}"
        self.http = httpx.Client(base_url=self.url, headers=headers, timeout=60)

    # -- PostgREST -------------------------------------------------------------
    def _check(self, r: httpx.Response) -> Any:
        if r.status_code >= 400:
            raise SupabaseError(f"{r.request.method} {r.request.url.path} -> {r.status_code}: {r.text[:500]}")
        if not r.content:
            return None
        return r.json()

    def select(self, table: str, params: dict[str, str] | None = None) -> list[dict]:
        return self._check(self.http.get(f"/rest/v1/{table}", params=params or {}))

    def select_all(self, table: str, params: dict[str, str], page: int = 1000) -> list[dict]:
        rows, offset = [], 0
        while True:
            batch = self.select(table, {**params, "limit": str(page), "offset": str(offset)})
            rows.extend(batch)
            if len(batch) < page:
                return rows
            offset += page

    def insert(self, table: str, rows: dict | list[dict], *, upsert_on: str | None = None,
               returning: bool = False) -> list[dict] | None:
        prefer = ["return=representation" if returning else "return=minimal"]
        params = {}
        if upsert_on:
            prefer.append("resolution=merge-duplicates")
            params["on_conflict"] = upsert_on
        r = self.http.post(f"/rest/v1/{table}", params=params, content=json.dumps(rows, default=str),
                           headers={"Prefer": ",".join(prefer), "Content-Type": "application/json"})
        return self._check(r)

    def insert_many(self, table: str, rows: Iterable[dict], chunk: int = 500, **kw: Any) -> None:
        buf: list[dict] = []
        for row in rows:
            buf.append(row)
            if len(buf) >= chunk:
                self.insert(table, buf, **kw)
                buf = []
        if buf:
            self.insert(table, buf, **kw)

    def update(self, table: str, match: dict[str, str], values: dict) -> None:
        params = {k: f"eq.{v}" for k, v in match.items()}
        r = self.http.patch(f"/rest/v1/{table}", params=params, content=json.dumps(values, default=str),
                            headers={"Prefer": "return=minimal", "Content-Type": "application/json"})
        self._check(r)

    def delete(self, table: str, params: dict[str, str]) -> None:
        self._check(self.http.delete(f"/rest/v1/{table}", params=params))

    def rpc(self, fn: str, args: dict | None = None) -> Any:
        r = self.http.post(f"/rest/v1/rpc/{fn}", content=json.dumps(args or {}, default=str),
                           headers={"Content-Type": "application/json"})
        return self._check(r)

    # -- Storage ---------------------------------------------------------------
    def download(self, bucket: str, path: str, dest, max_bytes: int) -> int:
        """Stream an object to `dest` (a binary file object), refusing anything over max_bytes."""
        total = 0
        with self.http.stream("GET", f"/storage/v1/object/{bucket}/{path}") as r:
            if r.status_code >= 400:
                r.read()
                raise SupabaseError(f"storage download failed ({r.status_code})")
            for chunk in r.iter_bytes(1 << 16):
                total += len(chunk)
                if total > max_bytes:
                    raise SupabaseError(f"archive exceeds the {max_bytes // (1 << 20)} MB limit")
                dest.write(chunk)
        return total

    def upload(self, bucket: str, path: str, data: bytes, content_type: str) -> None:
        r = self.http.post(f"/storage/v1/object/{bucket}/{path}", content=data,
                           headers={"Content-Type": content_type, "x-upsert": "true"})
        self._check(r)

    # -- Auth ------------------------------------------------------------------
    def user_from_token(self, token: str) -> dict | None:
        """Validate an end-user access token with Supabase Auth. Returns the user or None."""
        r = self.http.get("/auth/v1/user", headers={"Authorization": f"Bearer {token}"})
        if r.status_code != 200:
            return None
        return r.json()


_client: Supa | None = None


def client() -> Supa:
    global _client
    if _client is None:
        settings.require_supabase()
        _client = Supa()
    return _client
