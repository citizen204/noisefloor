"""Mailbox rule alerts.

A rule appears on a mailbox that files messages about invoices and payments
somewhere other than the inbox.  That is the signature of business email
compromise, and it is also what an accounts-payable clerk's mailbox looks like
on an ordinary Tuesday.  The keyword list is the same in both halves of this
pair, on purpose: it is the part of the alert that carries no information.
"""
from __future__ import annotations

from datetime import timedelta as T

from ..model import Alert, Event, GroundTruth, Scenario

_ALERT = dict(
    rule="EML-0012 Inbox rule created that hides or redirects finance mail",
    severity="high",
    technique="T1114.003",
    technique_name="Email Collection: Email Forwarding Rule",
)

BEC_RULE_TP = Scenario(
    id="mail-inboxrule-tp",
    title="New inbox rule filing invoice and payment mail out of the inbox",
    twin="mail-inboxrule-fp",
    tags=("email", "m365", "bec", "identity"),
    alert=Alert(
        summary="r.mathieson@corp.example created inbox rule \".\" matching "
                "invoice/payment/remittance/bank.",
        **_ALERT),
    events=[
        Event(T(minutes=-4), "okta", "user.authentication.auth_via_mfa", {
            "outcome": "SUCCESS", "actor": "r.mathieson@corp.example",
            "ip": "45.61.138.202", "factor": "Okta Verify Push",
            "note": "6 push notifications in 4 minutes: 5 denied by the user, "
                    "the 6th approved"}),
        Event(T(0), "okta", "user.session.start", {
            "outcome": "SUCCESS", "actor": "r.mathieson@corp.example",
            "ip": "45.61.138.202", "device": "unrecognised",
            "user_agent": "Chrome/129 Windows NT 10.0"}),
        Event(T(minutes=2), "m365", "New-InboxRule", {
            "user": "r.mathieson", "ip": "45.61.138.202", "ruleName": ".",
            "subjectOrBodyContains": "invoice, payment, remittance, bank",
            "moveToFolder": "RSS Feeds", "markAsRead": True, "deleteMessage": True}),
        Event(T(minutes=3), "m365", "MailItemsAccessed", {
            "user": "r.mathieson", "ip": "45.61.138.202",
            "note": "mailbox searched for \"remittance\"; 214 items returned"}),
        Event(T(minutes=11), "m365", "Send", {
            "user": "r.mathieson", "ip": "45.61.138.202",
            "inReplyTo": "RE: Ardmore Freight — INV-40118",
            "to": "accounts@ardmore-freight.example",
            "note": "reply into a live vendor thread; BSB and account number in the "
                    "signature block differ from the vendor's last 14 invoices"}),
        Event(T(minutes=14), "m365", "Set-Mailbox", {
            "user": "r.mathieson", "ip": "45.61.138.202",
            "forwardingSmtpAddress": "r.mathieson.ap@gmail.example",
            "result": "blocked by external-forwarding policy"}),
        Event(T(minutes=1), "edr", "asn.lookup", {
            "host": "-", "user": "-",
            "note": "45.61.138.202 is in a hosting/VPS range with no corporate "
                    "presence and no prior sign-in for this tenant"}),
        Event(T(days=-9), "edr", "ticket.opened", {
            "host": "-", "user": "r.mathieson",
            "note": "SD-87960: user asked the service desk how to create a rule "
                    "to file newsletters into a subfolder"}),
        Event(T(days=-1), "edr", "calendar.entry", {
            "host": "-", "user": "r.mathieson",
            "note": "user is at a logistics conference in Singapore this week"}),
    ],
    truth=GroundTruth(
        verdict="true-positive",
        rationale=(
            "The session was taken by wearing the user down: five denied pushes and a "
            "sixth approved, from a hosting address with no history in this tenant. "
            "The rule that follows does not file mail, it hides it — RSS Feeds, marked "
            "read, deleted — which serves no purpose for the mailbox owner, who can "
            "already see their own mail. Then the account searches for remittances and "
            "replies into a live vendor thread with altered bank details. The blocked "
            "external forward is the same hand reaching for a second channel."),
        decisive=[0, 1, 2, 3, 4, 5, 6],
        distractors=[7, 8],
        common_error=(
            "Treating the conference as explaining the new location. Travel explains a "
            "new country; it does not explain a hosting provider, and it does not "
            "explain five denied push prompts. A distractor that explains one field of "
            "one event is not an explanation of the session."),
        next_action=(
            "Revoke sessions and reset credentials, then delete the rule only after "
            "capturing it. Recover what the rule already swallowed out of RSS Feeds. "
            "Phone — do not email — Ardmore Freight's accounts team on a number from "
            "the existing contract to stop the payment, and check whether any other "
            "vendor thread received the same reply."),
    ),
)

BEC_RULE_FP = Scenario(
    id="mail-inboxrule-fp",
    title="New inbox rule filing invoice and payment mail out of the inbox",
    twin="mail-inboxrule-tp",
    tags=("email", "m365", "bec"),
    alert=Alert(
        summary="d.okafor@corp.example created inbox rule \"AP cover - Priya (leave)\" "
                "matching invoice/payment/remittance/bank.",
        **_ALERT),
    events=[
        Event(T(0), "okta", "user.session.start", {
            "outcome": "SUCCESS", "actor": "d.okafor@corp.example",
            "ip": "203.42.7.19", "device": "CORP-L4471 (managed, enrolled 2024-03)",
            "note": "the user's usual laptop, on the Adelaide office range"}),
        Event(T(minutes=6), "m365", "New-InboxRule", {
            "user": "d.okafor", "ip": "203.42.7.19",
            "ruleName": "AP cover - Priya (leave)",
            "subjectOrBodyContains": "invoice, payment, remittance, bank",
            "copyToFolder": "Accounts Payable",
            "forwardTo": "p.raghavan@corp.example"}),
        Event(T(hours=-3), "edr", "ticket.opened", {
            "host": "-", "user": "d.okafor",
            "note": "SD-88214: \"On leave 14 Oct - 1 Nov. Priya is covering AP. "
                    "How do I copy supplier invoices to her while I'm away?\" — "
                    "service desk replied with the inbox-rule steps"}),
        Event(T(days=-6), "edr", "hr.record", {
            "host": "-", "user": "d.okafor",
            "note": "annual leave 14 Oct - 1 Nov approved by line manager"}),
        Event(T(minutes=7), "m365", "rule.inspect", {
            "user": "d.okafor", "ruleName": "AP cover - Priya (leave)",
            "markAsRead": False, "deleteMessage": False, "moveToFolder": None,
            "note": "copy, not move; forward target is a licensed mailbox in the "
                    "same tenant; nothing leaves the organisation"}),
        Event(T(minutes=9), "m365", "MailItemsAccessed", {
            "user": "d.okafor", "ip": "203.42.7.19",
            "note": "user opened the Accounts Payable folder, 3 items, and sent one "
                    "to Priya manually"}),
        Event(T(days=-2), "okta", "user.session.start", {
            "outcome": "SUCCESS", "actor": "d.okafor@corp.example",
            "ip": "118.208.44.91",
            "note": "sign-in from an unfamiliar residential address; helpdesk note "
                    "the same day records a home internet provider change"}),
        Event(T(minutes=8), "edr", "detection.context", {
            "host": "-", "user": "-",
            "note": "the rule's keyword list matches the BEC rule template quoted in "
                    "EML-0012's own description, field for field"}),
    ],
    truth=GroundTruth(
        verdict="false-positive",
        rationale=(
            "The rule copies rather than moves, leaves messages unread and undeleted, "
            "and forwards to a mailbox inside the tenant — so nothing is hidden from "
            "the owner and nothing leaves the organisation. It was created on the "
            "user's enrolled laptop from the office range, three hours after a service "
            "desk ticket asking for exactly this, against leave dates HR approved a "
            "week earlier."),
        decisive=[0, 1, 2, 3, 4],
        distractors=[6, 7],
        common_error=(
            "Matching on the keyword list. \"invoice, payment, remittance, bank\" is "
            "the BEC signature and is also, unavoidably, what an accounts-payable "
            "clerk filters on. The keywords are what made the rule fire; they cannot "
            "then be the evidence that it is malicious. What separates the two halves "
            "of this pair is where the mail goes and who created the rule."),
        next_action=(
            "Close. Worth raising as a detection change rather than a ticket: EML-0012 "
            "fires on the keyword list alone, when the fields that carry the signal "
            "are already in the audit event — whether the rule deletes or marks read, "
            "and whether the forwarding target is outside the tenant."),
    ),
)

SCENARIOS = [BEC_RULE_TP, BEC_RULE_FP]
