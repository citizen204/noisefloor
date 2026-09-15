"""Rendering events as the log line an analyst would actually be looking at.

Each source gets its own shape.  An analyst reads Zeek's conn.log differently
from an Okta system log, and training on a uniform pretty-printed table teaches
a skill that does not transfer.  The formats here are simplified but keep the
field names and the ordering that people actually pattern-match on.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Sequence

from .model import Event, Scenario

_ISO = "%Y-%m-%dT%H:%M:%S"


def _iso(dt: datetime) -> str:
    return dt.strftime(_ISO) + "Z"


def _kv(fields: Dict[str, Any], keys: Sequence[str]) -> str:
    parts = []
    for k in keys:
        if k in fields:
            v = fields[k]
            parts.append("{}={}".format(k, json.dumps(v) if isinstance(v, str) and " " in v else v))
    for k, v in fields.items():
        if k not in keys:
            parts.append("{}={}".format(k, json.dumps(v) if isinstance(v, str) and " " in v else v))
    return " ".join(parts)


def _okta(ev: Event, ts: datetime) -> str:
    f = ev.fields
    return "{} okta eventType={} outcome={} actor={} ip={} {}".format(
        _iso(ts), ev.action, f.get("outcome", "-"), f.get("actor", "-"),
        f.get("ip", "-"),
        _kv({k: v for k, v in f.items() if k not in ("outcome", "actor", "ip")}, ()))


def _sysmon(ev: Event, ts: datetime) -> str:
    f = ev.fields
    extra = _kv({k: v for k, v in f.items()
                 if k not in ("event_id", "image", "parent_image", "command_line")}, ())
    line = "{} Sysmon/EventID={} Image={} ParentImage={}\n    CommandLine: {}".format(
        _iso(ts), f.get("event_id", 1), f.get("image", "-"), f.get("parent_image", "-"),
        f.get("command_line", "-"))
    return line + ("\n    " + extra if extra else "")


def _zeek(ev: Event, ts: datetime) -> str:
    f = ev.fields
    return "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}".format(
        _iso(ts), f.get("uid", "-"), f.get("id.orig_h", "-"), f.get("id.orig_p", "-"),
        f.get("id.resp_h", "-"), f.get("id.resp_p", "-"),
        f.get("service", "-"), f.get("note", f.get("duration", "-")))


def _cloudtrail(ev: Event, ts: datetime) -> str:
    f = dict(ev.fields)
    body = {
        "eventTime": _iso(ts),
        "eventName": ev.action,
        "userIdentity": {"arn": f.pop("arn", "-"), "type": f.pop("identity_type", "IAMUser")},
        "sourceIPAddress": f.pop("ip", "-"),
    }
    body.update(f)
    return json.dumps(body, indent=2)


def _auth(ev: Event, ts: datetime) -> str:
    f = ev.fields
    return "{} {} {}[{}]: {}".format(
        ts.strftime("%b %d %H:%M:%S"), f.get("host", "host"), f.get("proc", "sshd"),
        f.get("pid", 0), f.get("message", ev.action))


def _edr(ev: Event, ts: datetime) -> str:
    f = ev.fields
    return "{} edr {} host={} user={} {}".format(
        _iso(ts), ev.action, f.get("host", "-"), f.get("user", "-"),
        _kv({k: v for k, v in f.items() if k not in ("host", "user")}, ()))


_RENDERERS = {
    "okta": _okta, "sysmon": _sysmon, "zeek": _zeek,
    "cloudtrail": _cloudtrail, "auth": _auth, "edr": _edr,
}

#: A one-line reminder of what each source is, shown once per session.
SOURCE_HELP = {
    "okta": "identity provider sign-in and admin events",
    "sysmon": "Windows process creation and related host telemetry",
    "zeek": "network connection records (conn.log style)",
    "cloudtrail": "AWS control-plane API calls",
    "auth": "Linux authentication syslog",
    "edr": "endpoint agent detections and file events",
    "m365": "Microsoft 365 mailbox and Exchange audit events",
}


def render_event(ev: Event, anchor: datetime) -> str:
    renderer = _RENDERERS.get(ev.source)
    ts = ev.at(anchor)
    if renderer is None:
        return "{} {} {} {}".format(_iso(ts), ev.source, ev.action, _kv(ev.fields, ()))
    return renderer(ev, ts)


def render_evidence(scenario: Scenario, anchor: datetime,
                    reveal: Sequence[int] = None) -> List[str]:
    """Numbered evidence lines in time order.

    Indices shown to the analyst are the *scenario's* indices, not positions in
    this list, so a citation means the same thing however the events are sorted.
    """
    out: List[str] = []
    for i in scenario.ordered():
        if reveal is not None and i not in reveal:
            continue
        out.append("[{:>2}] {}  {}".format(
            i, scenario.events[i].source.ljust(10),
            render_event(scenario.events[i], anchor)))
    return out


def render_alert(scenario: Scenario, anchor: datetime) -> str:
    a = scenario.alert
    return (
        "  rule      {}\n"
        "  severity  {}\n"
        "  technique {} ({})\n"
        "  fired     {}\n\n"
        "  {}"
    ).format(a.rule, a.severity.upper(), a.technique, a.technique_name,
             _iso(anchor), a.summary)
