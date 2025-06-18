"""
Advanced MITMProxy Script: Redirect, Inject, Rewrite & Block
Author: Mohamed Yasar Arafath
Description:
  - Redirects specific domains
  - Blocks tracker URLs
  - Rewrites response content to filter keywords
  - Injects custom security headers
  - Logs each intercepted flow with timestamp
Usage:
  mitmproxy -s advanced_mitm_interceptor.py
"""

from mitmproxy import http, ctx
from datetime import datetime

REDIRECT_DOMAINS = {
    "example.com": "https://yasar-arafath.web.app",
    "tracking.example.net": "https://analytics.blocked.local"
}

BLOCKED_KEYWORDS = [b"ads", b"tracking", b"analytics"]
REPLACE_KEYWORDS = {
    b"Yasar": b"[REDACTED]",
    b"Admin": b"User"
}

BLOCKED_HOSTS = [
    "ads.example.com", 
    "en.softonic.com",
    "tracker.badsite.org"
]

CUSTOM_HEADERS = {
    "X-Intercepted-By": "MITMProxy-Interceptor",
    "X-Security-Policy": "Strict"
}


class AdvancedInterceptor:

    def request(self, flow: http.HTTPFlow) -> None:
        # Block malicious/tracker domains
        if flow.request.pretty_host in BLOCKED_HOSTS:
            flow.response = http.Response.make(
                403,
                b"Access Denied: This domain is blocked by policy.",
                {"Content-Type": "text/plain"}
            )
            self.log_flow(flow, blocked=True)
            return

        # Redirect domains
        for domain, redirect_url in REDIRECT_DOMAINS.items():
            if domain in flow.request.pretty_host:
                flow.response = http.Response.make(
                    302,
                    b"",
                    {"Location": redirect_url}
                )
                self.log_flow(flow, redirect=True)
                return

    def response(self, flow: http.HTTPFlow) -> None:
        # Inject headers
        for key, value in CUSTOM_HEADERS.items():
            flow.response.headers[key] = value

        # Modify response content if needed
        if flow.response.content:
            for word in BLOCKED_KEYWORDS:
                if word in flow.response.content:
                    flow.response.content = flow.response.content.replace(word, b"[BLOCKED]")

            for old, new in REPLACE_KEYWORDS.items():
                flow.response.content = flow.response.content.replace(old, new)

        self.log_flow(flow)

    def log_flow(self, flow: http.HTTPFlow, redirect=False, blocked=False) -> None:
        log_type = "NORMAL"
        if redirect:
            log_type = "REDIRECT"
        elif blocked:
            log_type = "BLOCKED"

        ctx.log.info(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {log_type} | {flow.request.method} {flow.request.pretty_url}")


addons = [AdvancedInterceptor()]

