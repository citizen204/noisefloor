"""Identity alerts.

Both scenarios below fire the same rule on the same pair of cities. The alert
text is almost word for word identical. Everything that separates them is in
the events.
"""
from __future__ import annotations

from datetime import timedelta as T

from ..model import Alert, Event, GroundTruth, Scenario

_ALERT = dict(
    rule="IDP-0031 Impossible travel",
    severity="high",
    technique="T1078.004",
    technique_name="Valid Accounts: Cloud Accounts",
)

IMPOSSIBLE_TRAVEL_TP = Scenario(
    id="identity-travel-tp",
    title="Impossible travel — Adelaide to Frankfurt in 22 minutes",
    twin="identity-travel-fp",
    tags=("identity", "okta", "mfa"),
    alert=Alert(
        summary="Successful sign-in for j.tan@corp.example from Adelaide (AU) and "
                "Frankfurt (DE), 14,200 km apart, 22 minutes apart.",
        **_ALERT),
    events=[
        Event(T(minutes=-6), "okta", "user.session.start", {
            "outcome": "SUCCESS", "actor": "j.tan@corp.example", "ip": "103.4.18.9",
            "city": "Adelaide", "asn": "AS4739 iiNet", "device_id": "D-8891",
            "user_agent": "Chrome/141 Windows"}),
        Event(T(minutes=-5), "okta", "user.authentication.auth_via_mfa", {
            "outcome": "SUCCESS", "actor": "j.tan@corp.example", "ip": "103.4.18.9",
            "factor": "Okta Verify Push", "device_id": "D-8891"}),
        Event(T(minutes=14), "okta", "user.authentication.auth_via_mfa", {
            "outcome": "DENIED", "actor": "j.tan@corp.example", "ip": "45.147.230.11",
            "factor": "Okta Verify Push", "attempt": "1 of 5"}),
        Event(T(minutes=15), "okta", "user.authentication.auth_via_mfa", {
            "outcome": "DENIED", "actor": "j.tan@corp.example", "ip": "45.147.230.11",
            "factor": "Okta Verify Push", "attempt": "4 of 5"}),
        Event(T(minutes=16), "okta", "user.authentication.auth_via_mfa", {
            "outcome": "SUCCESS", "actor": "j.tan@corp.example", "ip": "45.147.230.11",
            "factor": "Okta Verify Push", "attempt": "5 of 5"}),
        Event(T(minutes=16, seconds=20), "okta", "user.session.start", {
            "outcome": "SUCCESS", "actor": "j.tan@corp.example", "ip": "45.147.230.11",
            "city": "Frankfurt", "asn": "AS201814 MEVSPACE hosting",
            "device_id": "D-NEW-40f2", "user_agent": "Firefox/121 Linux"}),
        Event(T(minutes=18), "okta", "user.mfa.factor.activate", {
            "outcome": "SUCCESS", "actor": "j.tan@corp.example", "ip": "45.147.230.11",
            "factor": "Okta Verify (new device)", "note": "second factor enrolled"}),
        Event(T(minutes=19), "okta", "app.oauth2.token.grant", {
            "outcome": "SUCCESS", "actor": "j.tan@corp.example", "ip": "45.147.230.11",
            "scope": "Mail.Read Mail.Send", "client": "third-party IMAP bridge"}),
        Event(T(days=-88), "okta", "user.session.start", {
            "outcome": "SUCCESS", "actor": "j.tan@corp.example", "ip": "91.64.22.7",
            "city": "Frankfurt", "asn": "AS3320 Deutsche Telekom", "device_id": "D-8891",
            "note": "historical — user did travel to Germany in June"}),
    ],
    truth=GroundTruth(
        verdict="true-positive",
        rationale=(
            "The Frankfurt session is a different device with no prior history, reached "
            "after four denied push notifications and one approval on the fifth — the "
            "signature of MFA fatigue rather than a user unlocking their own phone. The "
            "attacker then enrolled their own second factor and granted mail scopes to an "
            "external client, which is persistence and collection, not travel."),
        decisive=[2, 3, 4, 6, 7],
        distractors=[8],
        common_error=(
            "Finding the June trip to Frankfurt and closing the ticket as 'user travels "
            "there'. That session came from a residential ASN on the user's known device; "
            "this one does not."),
        next_action=(
            "Revoke all sessions and OAuth grants, remove the factor enrolled at +18, force "
            "a password reset out of band, and check whether the mail scopes were used."),
    ),
)

IMPOSSIBLE_TRAVEL_FP = Scenario(
    id="identity-travel-fp",
    title="Impossible travel — Adelaide to Frankfurt in 19 minutes",
    twin="identity-travel-tp",
    tags=("identity", "okta", "vpn"),
    alert=Alert(
        summary="Successful sign-in for m.okafor@corp.example from Adelaide (AU) and "
                "Frankfurt (DE), 14,200 km apart, 19 minutes apart.",
        **_ALERT),
    events=[
        Event(T(minutes=-4), "okta", "user.session.start", {
            "outcome": "SUCCESS", "actor": "m.okafor@corp.example", "ip": "103.4.18.22",
            "city": "Adelaide", "asn": "AS4739 iiNet", "device_id": "D-5512",
            "user_agent": "Chrome/141 macOS"}),
        Event(T(minutes=-3), "okta", "user.authentication.auth_via_mfa", {
            "outcome": "SUCCESS", "actor": "m.okafor@corp.example", "ip": "103.4.18.22",
            "factor": "Okta Verify Push", "attempt": "1 of 1", "device_id": "D-5512"}),
        Event(T(minutes=14), "zeek", "vpn_tunnel_up", {
            "uid": "CqL7m2", "id.orig_h": "103.4.18.22", "id.orig_p": 51022,
            "id.resp_h": "51.89.14.60", "id.resp_p": 443,
            "service": "ssl", "note": "corp-vpn-fra01.corp.example — tunnel established"}),
        Event(T(minutes=15), "okta", "user.session.start", {
            "outcome": "SUCCESS", "actor": "m.okafor@corp.example", "ip": "51.89.14.60",
            "city": "Frankfurt", "asn": "AS16276 OVH hosting",
            "device_id": "D-5512", "user_agent": "Chrome/141 macOS"}),
        Event(T(minutes=15, seconds=10), "okta", "user.authentication.sso", {
            "outcome": "SUCCESS", "actor": "m.okafor@corp.example", "ip": "51.89.14.60",
            "app": "Confluence", "note": "existing session reused, no new factor prompt"}),
        Event(T(minutes=22), "okta", "user.session.start", {
            "outcome": "SUCCESS", "actor": "r.silva@corp.example", "ip": "51.89.14.60",
            "city": "Frankfurt", "asn": "AS16276 OVH hosting", "device_id": "D-7730",
            "note": "different employee, same egress address"}),
        Event(T(minutes=31), "okta", "user.session.start", {
            "outcome": "SUCCESS", "actor": "k.novak@corp.example", "ip": "51.89.14.60",
            "city": "Frankfurt", "asn": "AS16276 OVH hosting", "device_id": "D-2041",
            "note": "third employee, same egress address"}),
    ],
    truth=GroundTruth(
        verdict="false-positive",
        rationale=(
            "The Frankfurt session is the same device id and the same browser build as the "
            "Adelaide one, and it starts one minute after a VPN tunnel comes up to a host "
            "named corp-vpn-fra01. Two other employees sign in from the same address over "
            "the following quarter hour. This is the corporate VPN's European egress, and "
            "the geolocation is of the egress, not the user."),
        decisive=[2, 3, 5, 6],
        distractors=[4],
        common_error=(
            "Escalating on the hosting ASN. Corporate VPN egress almost always lands in "
            "hosting or cloud address space, so 'OVH' on its own means nothing — an attacker "
            "renting a box and a company renting a VPN concentrator look identical at the ASN."),
        next_action=(
            "Close, and raise a tuning request: the rule should suppress when the device id "
            "is unchanged and the destination address is a known VPN egress."),
    ),
)

SCENARIOS = [IMPOSSIBLE_TRAVEL_TP, IMPOSSIBLE_TRAVEL_FP]
