#!/usr/bin/env python3
"""True HTTP PRG delivery races on isolated file-backed sessions and cache.

Two operations in one session, unrelated intervening requests, an independent
browser session and simultaneous GETs use the exact Laravel Admin middleware.
No remote SSH or production endpoint is contacted.
"""
from __future__ import annotations

import concurrent.futures
import html
import http.cookiejar
import os
import re
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    base = os.environ.get("GATEWAY_BROWSER_BASE_URL", "")
    ports = [os.environ.get("GATEWAY_BROWSER_RACE_GET_ONE_URL", ""),
             os.environ.get("GATEWAY_BROWSER_RACE_GET_TWO_URL", "")]
    for origin in [base, *ports]:
        check(re.fullmatch(r"http://127\.0\.0\.1:\d{2,5}", origin) is not None,
              "Use only an explicit loopback fixture.")
    check(len(set([base, *ports])) == 3, "HTTP workers must be independent.")
    allowed = {urllib.parse.urlparse(origin).netloc for origin in [base, *ports]}

    def client():
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect()
        )

        def call(path, data=None):
            uri = urllib.parse.urljoin(base + "/", path)
            parsed = urllib.parse.urlparse(uri)
            check(parsed.netloc in allowed and (
                      parsed.path.startswith(("/admin", "/__browser__"))
                      or parsed.path == "/oauth/targets/callback"),
                  "Refuse nonfixture network requests.")
            body = urllib.parse.urlencode(data).encode("utf-8") if data is not None else None
            request = urllib.request.Request(
                uri, data=body, headers={"Accept": "text/html"},
                method="POST" if data is not None else "GET",
            )
            try:
                response = opener.open(request, timeout=20)
            except urllib.error.HTTPError as error:
                if error.code not in [301, 302, 303]:
                    raise
                response = error
            with response:
                return response.status, response.headers, response.read().decode("utf-8")

        return call

    first = client()
    response, headers, _ = first("/__browser__/experience/owner")
    check(response == 302, "Fixture login did not redirect to Admin.")
    response, _, page = first(headers["Location"])
    check(response == 200, "Admin page did not load.")
    token_match = re.search(r'name="_token"\s+value="([^"]+)"', page)
    check(token_match is not None, "Cannot retrieve the native Admin CSRF token.")
    csrf = token_match.group(1)

    def post(form_action, data):
        status, hdrs, _ = first(form_action, {"_token": csrf, **data})
        check(status == 302, "A form was not submitted natively.")
        result_url = hdrs["Location"]
        parsed = urllib.parse.urlparse(result_url)
        nonce = urllib.parse.parse_qs(parsed.query).get("_admin_feedback", [""])[0]
        check(re.fullmatch(r"[a-f0-9]{40}", nonce) is not None,
              "The POST did not receive a server-owned feedback token.")
        check(parsed.path.startswith("/admin/") and parsed.netloc == urllib.parse.urlparse(base).netloc,
              "Feedback redirect left the Admin origin.")
        check("password" not in result_url.lower() and "_token" not in result_url,
              "A credential or CSRF token leaked into the feedback URL.")
        return result_url

    verify_path = "/admin/targets/ui-ssh-connected/test"
    operation_path = "/admin/targets/ui-ssh-connected/operations"
    paused_error = "Resume Target operations before starting a new connection test."
    resumed_success = "Target operations resumed using the saved connection and permissions."

    # Other browser scenarios run against this same disposable database and
    # can leave the synthetic SSH Target resumed. Establish the exact
    # verification precondition through its actual Admin form rather than
    # relying on fixture-script order.
    initial_pause = post(operation_path, {"state": "paused"})
    code, _, pause_confirmation = first(initial_pause)
    check(code == 200 and "Target operations paused." in pause_confirmation,
          "Could not establish the paused SSH fixture precondition.")

    # 1. A same-session GET in another tab ages Laravel flash before the
    # original tab follows its redirect. It must see nothing and cannot steal.
    first_result = post(verify_path, {})
    status, _, other_page = first("/admin/targets")
    check(status == 200 and 'id="admin-feedback"' not in other_page
          and paused_error not in other_page,
          "An unrelated tab consumed the pending Verify result.")
    # Even a second authenticated session using the same user cannot claim it.
    second = client()
    status, headers, _ = second("/__browser__/experience/owner")
    check(status == 302, "Second browser login failed.")
    second(headers["Location"])
    status, _, leaked = second(first_result)
    check(status == 200 and paused_error not in leaked and 'id="admin-feedback"' not in leaked,
          "An unrelated session claimed the first tab's feedback.")
    # A tampered route or non-token query using the same result token must
    # not burn it before the correct redirect is followed.
    wrong_page = first_result.replace('/admin/targets/ui-ssh-connected', '/admin/targets')
    status, _, wrong = first(wrong_page)
    check(status == 200 and paused_error not in wrong and 'id="admin-feedback"' not in wrong,
          "A token on the wrong Admin route consumed the pending feedback.")
    status, _, wrong_filter = first(first_result + '&unexpected_filter=other_tab')
    check(status == 200 and paused_error not in wrong_filter
          and 'id="admin-feedback"' not in wrong_filter,
          "An altered redirect query consumed the pending feedback.")
    status, _, original = first(first_result)
    check(status == 200 and paused_error in original and 'id="admin-feedback"' in original,
          "The originating redirect lost Verify feedback after another session request.")
    status, _, replay = first(first_result)
    check(status == 200 and 'id="admin-feedback"' not in replay,
          "Reload replayed an already delivered result.")

    # 2. Two distinct POSTs from the same session are still pending.
    # Consume them in the reverse order of submission to prove no interchange.
    failure_url = post(verify_path, {})
    success_url = post(operation_path, {"state": "enabled"})
    status, _, success = first(success_url)
    check(status == 200 and resumed_success in success and paused_error not in success,
          "The second operation displayed the first operation's error.")
    status, _, failure = first(failure_url)
    check(status == 200 and paused_error in failure and resumed_success not in failure,
          "The first operation displayed the later operation's success.")
    status, _, other_page = first("/admin/targets")
    check(status == 200 and 'id="admin-feedback"' not in other_page,
          "A later unrelated GET replayed another tab's notice.")

    # 3. Race two requests for the exact same token against independent HTTP
    # workers. The cache's atomic claim must render one and only one result.
    paused_url = post(operation_path, {"state": "paused"})
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(
            lambda worker: first(worker + urllib.parse.urlparse(paused_url).path
                                 + "?" + urllib.parse.urlparse(paused_url).query),
            ports,
        ))
    check(all(response[0] == 200 for response in responses), "A concurrent Admin GET failed.")
    counts = [body.count('id="admin-feedback"') for _, _, body in responses]
    check(sorted(counts) == [0, 1], "Two simultaneous tabs both claimed a one-shot result.")
    _, _, reread = first(paused_url)
    check('id="admin-feedback"' not in reread, "A claimed result replayed.")

    def assert_correlated_get_result(call, location, destination, expected, label, *, prohibited=()):
        """A GET redirect's result must belong to the intended tab and path."""
        parsed = urllib.parse.urlparse(location)
        query = urllib.parse.parse_qs(parsed.query)
        token = query.get("_admin_feedback", [""])[0]
        check(parsed.netloc == urllib.parse.urlparse(base).netloc and parsed.path == destination,
              label + ": redirect changed its exact canonical destination.")
        check(re.fullmatch(r"[a-f0-9]{40}", token) is not None and set(query) == {"_admin_feedback"},
              label + ": GET redirect lacked an opaque one-use result token.")
        check(not any(value in location.lower() for value in
                      ("state=", "code=", "iss=", "password", "refresh_token", "fixture-authorization-code")),
              label + ": sensitive OAuth state/code escaped into the feedback URL.")

        # A query-tampered destination cannot consume or expose this result.
        status, _, wrong_query = call(location + "&unrelated_filter=1")
        check(status == 200 and expected not in wrong_query
              and 'id="admin-feedback"' not in wrong_query,
              label + ": wrong-filter GET consumed or exposed feedback.")

        other_page = "/admin/operations" if destination == "/admin/targets" else "/admin/targets"
        status, _, unrelated = call(other_page)
        check(status == 200 and expected not in unrelated
              and 'id="admin-feedback"' not in unrelated,
              label + ": an unrelated same-session tab stole the pending GET result.")
        status, _, delivered = call(location)
        check(status == 200 and expected in delivered
              and 'id="admin-feedback"' in delivered,
              label + ": the intended GET destination lost its one-use result.")
        check(not any(value in delivered for value in prohibited),
              label + ": an unrelated result was mixed into the destination.")
        status, _, replay = call(location)
        check(status == 200 and expected not in replay
              and 'id="admin-feedback"' not in replay,
              label + ": reload replayed a consumed GET result.")
        return delivered

    # 4. Exercise the actual production WordPress callback route/controller
    # through a disposable registered Target and mocked loopback HTTP provider.
    # Its callback is GET-originated and outside the correlated Admin route.
    oauth = client()
    status, headers, _ = oauth("/__browser__/enter")
    check(status == 302, "WordPress fixture owner login failed.")
    status, _, page = oauth(headers["Location"])
    check(status == 200, "WordPress fixture Target page failed.")
    oauth_csrf_match = re.search(r'name="_token"\s+value="([^"]+)"', page)
    check(oauth_csrf_match is not None, "WordPress fixture CSRF token absent.")
    oauth_csrf = oauth_csrf_match.group(1)

    # Start by consuming an ordinary correlated POST result. Old middleware
    # kept its suppression marker alive for ten minutes and erased callbacks.
    status, hdr, _ = oauth("/admin/targets/browser-wp/test", {"_token": oauth_csrf})
    check(status == 302 and "_admin_feedback=" in hdr["Location"],
          "Expected a correlated Target test result before callback.")
    prior_token_url = hdr["Location"]
    # The first unrelated Admin GET still carries POST flash provenance.
    # A handoff rejection generated by this GET must create an independent
    # new flash despite the previous POST being pending and unconsumed.
    missing_handoff = "/admin/targets/browser-wp/external-authorization/" + "f" * 32
    status, hdr, _ = oauth(missing_handoff)
    check(status == 302, "Missing handoff did not redirect.")
    handoff_first_error = assert_correlated_get_result(
        oauth, hdr["Location"], "/admin/targets/browser-wp",
        "Authorization handoff expired or was already used.",
        "Pending POST + new GET handoff rejection")
    status, _, original_post_page = oauth(prior_token_url)
    check(status == 200, "The original correlated POST result was lost after the handoff GET.")
    check("Authorization handoff expired or was already used." not in original_post_page,
          "The original POST result wrongly displayed the GET handoff error.")

    status, hdr, _ = oauth("/admin/targets/browser-wp/connect", {"_token": oauth_csrf})
    check(status == 303, "Actual WordPress connect did not initiate a 303 handoff.")
    handoff_path = hdr["Location"]
    status, _, handoff_page = oauth(handoff_path)
    check(status == 200, "Actual handoff was not consumed successfully.")
    match = re.search(r'<meta http-equiv="refresh" content="0;url=([^"]+)"', handoff_page)
    check(match is not None, "Actual handoff did not contain the verified provider transition.")
    provider_url = html.unescape(match.group(1))
    parameters = urllib.parse.parse_qs(urllib.parse.urlparse(provider_url).query)
    check(bool(parameters.get("state")), "Actual provider handoff omitted OAuth state.")
    actual_state = parameters["state"][0]

    callback_query = urllib.parse.urlencode({
        "state": actual_state,
        "code": "fixture-authorization-code",
        "iss": "https://provider.browser.test",
    })
    status, hdr, _ = oauth("/oauth/targets/callback?" + callback_query)
    check(status == 302, "Actual successful OAuth callback did not redirect.")
    check(urllib.parse.urlparse(hdr["Location"]).path == "/admin/targets/browser-wp",
          "Successful OAuth callback did not target its own Target.")
    authorized = assert_correlated_get_result(
        oauth, hdr["Location"], "/admin/targets/browser-wp",
        "WordPress Target authorization completed.", "Successful OAuth callback")

    # Explicit separate POST then fresh invalid-state callback: the error
    # category and log reference must be visible and nonrepeating as well.
    status, hdr, _ = oauth("/admin/targets/browser-wp/operations",
                          {"_token": oauth_csrf, "state": "paused"})
    check(status == 302 and "_admin_feedback=" in hdr["Location"],
          "Second correlated POST did not receive a result token.")
    status, _, _ = oauth(hdr["Location"])
    check(status == 200, "Second correlated result did not render.")
    status, hdr, _ = oauth("/oauth/targets/callback?state=invalid_fixture_state&code=invalid")
    check(status == 302 and urllib.parse.urlparse(hdr["Location"]).path == "/admin/targets",
          "Actual OAuth callback rejection did not return to Admin Targets.")
    rejected = assert_correlated_get_result(
        oauth, hdr["Location"], "/admin/targets", "invalid_state",
        "Failed OAuth callback", prohibited=("WordPress Target authorization completed.",))
    check("Log reference" in rejected and
          re.search(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', rejected),
          "Failed OAuth callback lost its diagnostic correlation reference.")

    # The original handoff is now already consumed. Its actual GET-generated
    # rejection must remain visible after the earlier POST result was shown.
    status, hdr, _ = oauth(handoff_path)
    check(status == 302, "Reused external authorization handoff did not reject.")
    stale_handoff = assert_correlated_get_result(
        oauth, hdr["Location"], "/admin/targets/browser-wp",
        "Authorization handoff expired or was already used.",
        "Reused GET handoff", prohibited=("WordPress Target authorization completed.",))

    print("PASS: real OAuth callback success/failure and expired GET-handoff destination-bound one-use feedback survive same-session unrelated tab GETs.")
    print("PASS: real HTTP interleaved tab GET, separate login session, wrong-route/query claim defense, "
          "inverse-order POST results, atomic simultaneous claim, and no replay")


if __name__ == "__main__":
    main()
