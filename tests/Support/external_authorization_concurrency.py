#!/usr/bin/env python3
"""Controlled real-HTTP race against disposable, file-backed Laravel sessions/cache.

The shell fixture starts four independent PHP server workers. Both handoff GETs
and an unrelated session writer rendezvous *after* StartSession reads its file.
The writer resumes only after both GET responses, deliberately restoring the
old session snapshot. The independent atomic claim must reject every replay.
"""

from __future__ import annotations

import concurrent.futures
import http.cookiejar
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ConnectForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_connect_form = False
        self.csrf = None

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "form":
            self.in_connect_form = (
                values.get("method", "").upper() == "POST"
                and urllib.parse.urlparse(values.get("action", "")).path.endswith(
                    "/admin/targets/browser-wp/connect"
                )
            )
        elif tag == "input" and self.in_connect_form and values.get("name") == "_token":
            self.csrf = values.get("value")

    def handle_endtag(self, tag):
        if tag == "form":
            self.in_connect_form = False


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    base = os.environ.get("GATEWAY_BROWSER_BASE_URL", "")
    check(re.fullmatch(r"http://127\.0\.0\.1:\d{2,5}", base) is not None,
          "The concurrency fixture must use a loopback-only HTTP origin.")

    worker_one = os.environ.get("GATEWAY_BROWSER_RACE_GET_ONE_URL", "")
    worker_two = os.environ.get("GATEWAY_BROWSER_RACE_GET_TWO_URL", "")
    for worker in (worker_one, worker_two):
        check(re.fullmatch(r"http://127\.0\.0\.1:\d{2,5}", worker) is not None,
              "Every worker must listen on its own loopback origin.")
    permitted_origins = {urllib.parse.urlparse(value).netloc
                         for value in (base, worker_one, worker_two)}
    check(len(permitted_origins) == 3, "HTTP workers must use three distinct ports.")

    cookiejar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookiejar), NoRedirect()
    )

    def request(path, *, data=None):
        url = urllib.parse.urljoin(base + "/", path)
        check(urllib.parse.urlparse(url).netloc in permitted_origins,
              "The test may request only its three local fixtures.")
        req = urllib.request.Request(
            url, data=data, headers={"Accept": "text/html", "Content-Type": "application/x-www-form-urlencoded"},
            method="POST" if data is not None else "GET",
        )
        try:
            with opener.open(req, timeout=20) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            if 300 <= error.code < 400:
                return error.code, error.headers, error.read()
            raise RuntimeError(
                f'HTTP {error.code} at local fixture route {urllib.parse.urlparse(url).path}'
            ) from error

    def follow_once(path):
        status, headers, _ = request(path)
        check(status in (301, 302, 303), "Unexpected login bootstrap response.")
        location = headers.get("Location", "")
        check(bool(location), "Missing login redirect.")
        return request(location)

    status, _, target_page = follow_once("/__browser__/enter")
    check(status == 200, "Fixture login did not reach the Target page.")
    form = ConnectForm()
    form.feed(target_page.decode("utf-8"))
    check(bool(form.csrf), "Target connect CSRF field missing.")

    status, headers, _ = request(
        "/admin/targets/browser-wp/connect",
        data=urllib.parse.urlencode({"_token": form.csrf}).encode(),
    )
    check(status == 303, "Connector POST must end in same-origin 303.")
    location = headers.get("Location", "")
    url = urllib.parse.urlparse(urllib.parse.urljoin(base + "/", location))
    check(url.netloc == urllib.parse.urlparse(base).netloc, "Cross-origin POST redirect.")
    check(re.fullmatch(r"/admin/targets/browser-wp/external-authorization/[a-f0-9]{32}",
                       url.path) is not None, "Unexpected handoff location.")
    check("state=" not in location, "OAuth state leaked through internal handoff URL.")
    handoff = url.path.rsplit("/", 1)[-1]
    race = secrets.token_hex(8)
    concurrent_get = url.path + "?fixture_race=" + race
    writer = "/__browser__/stale-session-writer?fixture_race=" + race

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        first = pool.submit(request, worker_one + concurrent_get)
        second = pool.submit(request, worker_two + concurrent_get)
        stale_writer = pool.submit(request, writer)
        try:
            get_responses = [first.result(timeout=18), second.result(timeout=18)]
            check(sorted(result[0] for result in get_responses) == [200, 302],
                  "Two simultaneous GETs must produce exactly one provider document.")
            document = next(body for code, _, body in get_responses if code == 200)
            check(b'http-equiv="refresh"' in document and b'provider.browser.test' in document,
                  "The winning GET did not produce the safe provider transition document.")
        finally:
            request("/__browser__/race-release/" + race)
        check(stale_writer.result(timeout=18)[0] == 200,
              "The concurrent unrelated session writer did not finish.")

    status, _, body = request("/__browser__/handoff-present/" + handoff)
    check(status == 200, "Could not inspect the stale writer's session snapshot.")
    check(json.loads(body.decode("utf-8")).get("stale_entry_present") is True,
          "The fixture did not reproduce a stale session writer restoring the handoff.")

    check(request(url.path)[0] == 302, "A restored stale session entry was replayed.")
    check(request(url.path)[0] == 302, "A consumed handoff became reusable.")
    print("PASS: real HTTP across independent PHP workers uses shared encrypted file sessions and atomic file-cache claims.")
    print("PASS: exactly one of two simultaneous authorization GETs returns the provider document.")
    print("PASS: a delayed unrelated Admin session writer restores stale data but cannot replay the claim.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FAIL: Admin external authorization HTTP concurrency: {exc}", file=sys.stderr)
        sys.exit(1)
