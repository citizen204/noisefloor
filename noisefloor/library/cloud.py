"""Cloud credential alerts.

A long-lived access key appears from an address it has never been used from.
Whether that is a leak or a build agent moving depends entirely on what the key
did next.
"""
from __future__ import annotations

from datetime import timedelta as T

from ..model import Alert, Event, GroundTruth, Scenario

_ALERT = dict(
    rule="CLD-0044 IAM access key used from unfamiliar network",
    severity="high",
    technique="T1078.004",
    technique_name="Valid Accounts: Cloud Accounts",
)

KEY_LEAK_TP = Scenario(
    id="cloud-keyuse-tp",
    title="Access key used from an address it has never been seen from",
    twin="cloud-keyuse-fp",
    tags=("cloud", "aws", "cloudtrail"),
    alert=Alert(
        summary="AKIA...K7QF (svc-reporting) called AWS APIs from 194.110.13.44, "
                "an address with no prior history for this key.",
        **_ALERT),
    events=[
        Event(T(0), "cloudtrail", "GetCallerIdentity", {
            "arn": "arn:aws:iam::4418:user/svc-reporting", "ip": "194.110.13.44",
            "awsRegion": "us-east-1", "userAgent": "aws-cli/2.15.0 Python/3.11 Linux"}),
        Event(T(seconds=40), "cloudtrail", "ListBuckets", {
            "arn": "arn:aws:iam::4418:user/svc-reporting", "ip": "194.110.13.44",
            "awsRegion": "us-east-1", "userAgent": "aws-cli/2.15.0 Python/3.11 Linux"}),
        Event(T(minutes=1, seconds=10), "cloudtrail", "GetAccountAuthorizationDetails", {
            "arn": "arn:aws:iam::4418:user/svc-reporting", "ip": "194.110.13.44",
            "awsRegion": "us-east-1", "errorCode": "AccessDenied"}),
        Event(T(minutes=2), "cloudtrail", "ListUsers", {
            "arn": "arn:aws:iam::4418:user/svc-reporting", "ip": "194.110.13.44",
            "awsRegion": "us-east-1", "errorCode": "AccessDenied"}),
        Event(T(minutes=4), "cloudtrail", "GetObject", {
            "arn": "arn:aws:iam::4418:user/svc-reporting", "ip": "194.110.13.44",
            "awsRegion": "ap-southeast-2", "bucket": "corp-reporting-exports",
            "note": "1,940 GetObject calls over the following 11 minutes"}),
        Event(T(minutes=17), "cloudtrail", "CreateAccessKey", {
            "arn": "arn:aws:iam::4418:user/svc-reporting", "ip": "194.110.13.44",
            "awsRegion": "us-east-1", "errorCode": "AccessDenied",
            "note": "attempted to mint a second key for the same user"}),
        Event(T(days=-2), "edr", "secret.exposed", {
            "host": "-", "user": "-",
            "note": "AKIA...K7QF appeared in a public GitHub Gist two days ago "
                    "(found by retro-hunt, not alerted at the time)"}),
        Event(T(minutes=-90), "cloudtrail", "GetObject", {
            "arn": "arn:aws:iam::4418:user/svc-reporting", "ip": "13.55.20.9",
            "awsRegion": "ap-southeast-2", "bucket": "corp-reporting-exports",
            "note": "the key's normal nightly job, from the usual address"}),
    ],
    truth=GroundTruth(
        verdict="true-positive",
        rationale=(
            "The first four calls are textbook orientation: who am I, what buckets exist, "
            "what can I do — with the two IAM enumeration calls denied. Nothing legitimate "
            "starts a session by asking who it is. The key then pulls nearly two thousand "
            "objects and tries to mint a second key, and it had been published in a public "
            "Gist two days earlier."),
        decisive=[0, 2, 3, 4, 5, 6],
        distractors=[7],
        common_error=(
            "Anchoring on the AccessDenied results and concluding nothing happened. The "
            "denials are the recon; the GetObject burst that succeeded is the incident."),
        next_action=(
            "Deactivate the key immediately rather than deleting it, so the trail stays "
            "attributable; scope the 1,940 objects read; rotate anything those exports "
            "contained; and check whether the Gist exposed other secrets."),
    ),
)

KEY_LEAK_FP = Scenario(
    id="cloud-keyuse-fp",
    title="Access key used from an address it has never been seen from",
    twin="cloud-keyuse-tp",
    tags=("cloud", "aws", "cloudtrail", "ci"),
    alert=Alert(
        summary="AKIA...M2VD (svc-ci-deploy) called AWS APIs from 20.29.134.17, "
                "an address with no prior history for this key.",
        **_ALERT),
    events=[
        Event(T(minutes=-6), "edr", "ci.run_started", {
            "host": "-", "user": "-",
            "note": "GitHub Actions run 18844213 for corp/platform, workflow deploy.yml, "
                    "commit 4c1e90a on main"}),
        Event(T(0), "cloudtrail", "AssumeRole", {
            "arn": "arn:aws:iam::4418:user/svc-ci-deploy", "ip": "20.29.134.17",
            "awsRegion": "ap-southeast-2", "roleArn": "arn:aws:iam::4418:role/deploy-platform",
            "userAgent": "aws-cli/2.15.0 Python/3.11 Linux"}),
        Event(T(seconds=30), "cloudtrail", "PutObject", {
            "arn": "arn:aws:sts::4418:assumed-role/deploy-platform/ci",
            "ip": "20.29.134.17", "awsRegion": "ap-southeast-2",
            "bucket": "corp-platform-artifacts", "key": "builds/4c1e90a/bundle.tar.gz"}),
        Event(T(minutes=1), "cloudtrail", "UpdateFunctionCode", {
            "arn": "arn:aws:sts::4418:assumed-role/deploy-platform/ci",
            "ip": "20.29.134.17", "awsRegion": "ap-southeast-2",
            "functionName": "platform-api", "note": "same three calls as every deploy"}),
        Event(T(minutes=2), "edr", "asn.lookup", {
            "host": "-", "user": "-",
            "note": "20.29.134.17 is in AS8075 Microsoft, inside the published "
                    "GitHub Actions egress ranges"}),
        Event(T(days=-4), "edr", "config.change", {
            "host": "-", "user": "-",
            "note": "runner pool migrated from self-hosted (13.55.x) to GitHub-hosted, "
                    "change CHG-4471"}),
        Event(T(minutes=3), "cloudtrail", "GetCallerIdentity", {
            "arn": "arn:aws:sts::4418:assumed-role/deploy-platform/ci",
            "ip": "20.29.134.17", "awsRegion": "ap-southeast-2",
            "note": "the deploy script logs its identity on every run"}),
    ],
    truth=GroundTruth(
        verdict="false-positive",
        rationale=(
            "The key immediately assumes its usual deployment role and makes the same three "
            "calls this pipeline makes on every release, against the artefact bucket and "
            "function it always touches, with a commit SHA that matches a real CI run six "
            "minutes earlier. The address is in GitHub's published Actions range, and a "
            "change record four days ago moved the runner pool off self-hosted — which is "
            "exactly why the address is new."),
        decisive=[0, 1, 2, 3, 4, 5],
        distractors=[6],
        common_error=(
            "Seeing GetCallerIdentity and matching it to the recon pattern. Position "
            "matters: as the first call of a session from a strange address it is "
            "orientation, and after a successful deploy from a known pipeline it is a "
            "script logging what it ran as."),
        next_action=(
            "Close, and add the GitHub Actions ranges to the key's expected-source list. "
            "Separately, note that a long-lived key is still doing this job — OIDC would "
            "remove the credential entirely."),
    ),
)

SCENARIOS = [KEY_LEAK_TP, KEY_LEAK_FP]
