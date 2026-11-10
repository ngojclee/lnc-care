"""Provider OAuth, channel discovery, and Graph/TikTok/YouTube API transport."""
import time
from urllib.parse import urlencode

import httpx

META_VERSION = "v22.0"
TIKTOK_VERSION = "v1.3"
YOUTUBE_VERSION = "v3"

META_SCOPES = (
    "pages_show_list",
    "pages_read_engagement",
    "pages_read_user_content",
    "pages_manage_engagement",
    "pages_manage_metadata",
    "read_insights",
    "instagram_basic",
    "instagram_manage_comments",
    "instagram_manage_insights",
    "business_management",
)

METRIC_MAP = {
    "fb_page": {
        "impressions": "post_impressions_unique",
        "reactions": "post_reactions_by_type_total",
        "clicks": "post_clicks",
        "followers": "followers_count",
    },
    "ig_account": {
        "reach": "reach",
        "saves": "saved",
        "shares": "shares",
        "plays": "views",
        "followers": "followers_count",
    },
}


class ProviderError(Exception):
    def __init__(self, code: str, status: int = 502):
        super().__init__(code)
        self.code = code
        self.status = status


class Providers:
    def __init__(self, transport=None):
        self._transport = transport

    def _client(self) -> httpx.Client:
        return httpx.Client(
            transport=self._transport,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(20.0, connect=5.0),
        )

    def authorize(
        self, provider: str, app: dict, secret: dict, redirect_uri: str, state: str, verifier: str
    ) -> str:
        if provider == "meta":
            params = {
                "client_id": app["client_id"],
                "redirect_uri": redirect_uri,
                "state": state,
                "response_type": "code",
                "scope": ",".join(META_SCOPES),
            }
            return f"https://www.facebook.com/{META_VERSION}/dialog/oauth?{urlencode(params)}"
        if provider == "tiktok":
            params = {
                "app_id": app["client_id"],
                "redirect_uri": redirect_uri,
                "state": state,
            }
            return f"https://business-api.tiktok.com/portal/auth?{urlencode(params)}"
        if provider == "youtube":
            params = {
                "client_id": app["client_id"],
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": "https://www.googleapis.com/auth/youtube.force-ssl",
                "access_type": "offline",
                "prompt": "consent",
                "state": state,
            }
            return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
        raise ProviderError("provider_not_supported", 422)

    def exchange(
        self, provider: str, app: dict, secret: dict, redirect_uri: str, code: str, verifier: str
    ) -> dict:
        with self._client() as client:
            if provider == "meta":
                res = client.get(
                    f"https://graph.facebook.com/{META_VERSION}/oauth/access_token",
                    params={
                        "client_id": app["client_id"],
                        "client_secret": secret["client_secret"],
                        "redirect_uri": redirect_uri,
                        "code": code,
                    },
                )
                if res.status_code != 200:
                    raise ProviderError("oauth_exchange_failed", 502)
                data = res.json()
                short_token = data.get("access_token")
                if not short_token:
                    raise ProviderError("oauth_exchange_failed", 502)
                # Exchange for long-lived user token when supported
                ll = client.get(
                    f"https://graph.facebook.com/{META_VERSION}/oauth/access_token",
                    params={
                        "grant_type": "fb_exchange_token",
                        "client_id": app["client_id"],
                        "client_secret": secret["client_secret"],
                        "fb_exchange_token": short_token,
                    },
                )
                if ll.status_code == 200 and ll.json().get("access_token"):
                    ll_data = ll.json()
                    return {
                        "access_token": ll_data["access_token"],
                        "expires_in": int(ll_data.get("expires_in", 5184000)),
                    }
                return {
                    "access_token": short_token,
                    "expires_in": int(data.get("expires_in", 5184000)),
                }
            if provider == "tiktok":
                res = client.post(
                    f"https://business-api.tiktok.com/open_api/{TIKTOK_VERSION}/oauth2/access_token/",
                    json={
                        "app_id": app["client_id"],
                        "secret": secret["client_secret"],
                        "auth_code": code,
                    },
                )
                if res.status_code != 200:
                    raise ProviderError("oauth_exchange_failed", 502)
                payload = res.json().get("data") or {}
                if not payload.get("access_token"):
                    raise ProviderError("oauth_exchange_failed", 502)
                return {
                    "access_token": payload["access_token"],
                    "expires_in": int(payload.get("expires_in", 86400 * 30)),
                }
            if provider == "youtube":
                res = client.post(
                    "https://oauth2.googleapis.com/token",
                    data={
                        "client_id": app["client_id"],
                        "client_secret": secret["client_secret"],
                        "redirect_uri": redirect_uri,
                        "code": code,
                        "grant_type": "authorization_code",
                    },
                )
                if res.status_code != 200:
                    raise ProviderError("oauth_exchange_failed", 502)
                data = res.json()
                if not data.get("access_token"):
                    raise ProviderError("oauth_exchange_failed", 502)
                return {
                    "access_token": data["access_token"],
                    "refresh_token": data.get("refresh_token", ""),
                    "expires_in": int(data.get("expires_in", 3600)),
                }
        raise ProviderError("provider_not_supported", 422)

    def discover(self, provider: str, app: dict, secret: dict, access_token: str) -> dict:
        if provider != "meta":
            return {"channels": [], "truncated": False}
        with self._client() as client:
            res = client.get(
                f"https://graph.facebook.com/{META_VERSION}/me/accounts",
                params={
                    "fields": "id,name,username,followers_count,access_token,tasks,"
                    "instagram_business_account{id,username,name,followers_count}",
                    "limit": 50,
                },
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if res.status_code == 401:
                raise ProviderError("provider_unauthorized", 401)
            if res.status_code != 200:
                raise ProviderError("provider_discovery_failed", 502)
            body = res.json()
            pages = body.get("data") or []
            channels = []
            for p in pages:
                page_id = str(p.get("id", "")).strip()
                if not page_id:
                    continue
                page_token = p.get("access_token") or access_token
                channels.append(
                    {
                        "external_id": page_id,
                        "name": p.get("name") or f"Page {page_id}",
                        "handle": p.get("username") or "",
                        "kind": "fb_page",
                        "adapter": "meta_api",
                        "followers_count": int(p.get("followers_count") or 0),
                        "linked_external_id": None,
                        "page_access_token": page_token,
                        "eligible": True,
                    }
                )
                ig = p.get("instagram_business_account")
                if isinstance(ig, dict) and ig.get("id"):
                    ig_id = str(ig["id"]).strip()
                    channels.append(
                        {
                            "external_id": ig_id,
                            "name": ig.get("name") or f"@{ig.get('username', ig_id)}",
                            "handle": f"@{ig['username']}" if ig.get("username") else "",
                            "kind": "ig_account",
                            "adapter": "meta_api",
                            "followers_count": int(ig.get("followers_count") or 0),
                            "linked_external_id": page_id,
                            "page_access_token": page_token,
                            "eligible": True,
                        }
                    )
            return {
                "channels": channels,
                "truncated": bool((body.get("paging") or {}).get("next")),
            }

    def fetch_channel_posts(
        self, kind: str, external_id: str, token: str, *, limit: int = 20
    ) -> list[dict]:
        with self._client() as client:
            if kind == "fb_page":
                res = client.get(
                    f"https://graph.facebook.com/{META_VERSION}/{external_id}/published_posts",
                    params={
                        "fields": "id,message,permalink_url,created_time,attachments{media_type,url,media}",
                        "limit": max(1, min(50, limit)),
                    },
                    headers={"Authorization": f"Bearer {token}"},
                )
                if res.status_code != 200:
                    raise ProviderError("provider_posts_fetch_failed", 502)
                rows = res.json().get("data") or []
                out = []
                for r in rows:
                    media = []
                    for att in (r.get("attachments") or {}).get("data") or []:
                        img = ((att.get("media") or {}).get("image") or {}).get("src") or att.get("url")
                        if img:
                            media.append({"type": att.get("media_type", "photo"), "url": img})
                    out.append(
                        {
                            "external_id": str(r["id"]),
                            "caption": r.get("message") or "",
                            "permalink": r.get("permalink_url") or "",
                            "kind": "post",
                            "published_at": int(time.time()),
                            "media": media,
                        }
                    )
                return out
            if kind == "ig_account":
                res = client.get(
                    f"https://graph.facebook.com/{META_VERSION}/{external_id}/media",
                    params={
                        "fields": "id,caption,media_type,media_url,thumbnail_url,permalink,timestamp,like_count,comments_count",
                        "limit": max(1, min(50, limit)),
                    },
                    headers={"Authorization": f"Bearer {token}"},
                )
                if res.status_code != 200:
                    raise ProviderError("provider_posts_fetch_failed", 502)
                rows = res.json().get("data") or []
                out = []
                for r in rows:
                    m_url = r.get("media_url") or r.get("thumbnail_url")
                    media = [{"type": (r.get("media_type") or "IMAGE").lower(), "url": m_url}] if m_url else []
                    out.append(
                        {
                            "external_id": str(r["id"]),
                            "caption": r.get("caption") or "",
                            "permalink": r.get("permalink") or "",
                            "kind": "reel" if r.get("media_type") == "VIDEO" else "post",
                            "published_at": int(time.time()),
                            "media": media,
                            "likes": int(r.get("like_count") or 0),
                            "comments_count": int(r.get("comments_count") or 0),
                        }
                    )
                return out
        return []

    def fetch_post_comments(
        self, kind: str, post_external_id: str, token: str, *, limit: int = 50
    ) -> list[dict]:
        with self._client() as client:
            if kind == "fb_page":
                res = client.get(
                    f"https://graph.facebook.com/{META_VERSION}/{post_external_id}/comments",
                    params={
                        "fields": "id,from,message,created_time,parent,is_hidden,comment_count,like_count",
                        "filter": "stream",
                        "limit": max(1, min(100, limit)),
                    },
                    headers={"Authorization": f"Bearer {token}"},
                )
                if res.status_code != 200:
                    raise ProviderError("provider_comments_fetch_failed", 502)
                rows = res.json().get("data") or []
                out = []
                for r in rows:
                    frm = r.get("from") or {}
                    parent = (r.get("parent") or {}).get("id")
                    out.append(
                        {
                            "external_id": str(r["id"]),
                            "parent_external_id": str(parent) if parent else None,
                            "author_external_id": str(frm.get("id") or ""),
                            "author_name": frm.get("name") or "Facebook User",
                            "text": r.get("message") or "",
                            "is_hidden": bool(r.get("is_hidden")),
                            "like_count": int(r.get("like_count") or 0),
                            "reply_count": int(r.get("comment_count") or 0),
                            "created_at": int(time.time()),
                        }
                    )
                return out
            if kind == "ig_account":
                res = client.get(
                    f"https://graph.facebook.com/{META_VERSION}/{post_external_id}/comments",
                    params={
                        "fields": "id,text,username,timestamp,hidden,like_count",
                        "limit": max(1, min(100, limit)),
                    },
                    headers={"Authorization": f"Bearer {token}"},
                )
                if res.status_code != 200:
                    raise ProviderError("provider_comments_fetch_failed", 502)
                rows = res.json().get("data") or []
                return [
                    {
                        "external_id": str(r["id"]),
                        "parent_external_id": None,
                        "author_external_id": str(r.get("username") or ""),
                        "author_name": f"@{r['username']}" if r.get("username") else "Instagram User",
                        "text": r.get("text") or "",
                        "is_hidden": bool(r.get("hidden")),
                        "like_count": int(r.get("like_count") or 0),
                        "reply_count": 0,
                        "created_at": int(time.time()),
                    }
                    for r in rows
                ]
        return []
