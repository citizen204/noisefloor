# noisefloor

**A SOC triage drill that grades your reasoning, not just your verdict.**

```
noisefloor drill -n 3
```

Most blue-team training asks *is this a real incident?* and marks the answer.
That is one bit, and it is the bit that transfers least. Half the analysts who
call a scenario correctly do it from something that merely correlates — and
they will call the next one wrong.

So `noisefloor` asks for two things: the verdict, **and the events you relied
on**. Then it tells you which of five things just happened.

---

## The five outcomes

| | |
|---|---|
| **sound** | Right verdict, from the evidence that settles it. |
| **right-via-distractor** | Right verdict, reached partly through evidence designed to mislead. |
| **right-by-accident** | Right verdict, but not from the evidence that settles it. **This does not pass.** |
| **wrong-despite-evidence** | Wrong verdict, from the right evidence read backwards. |
| **wrong-and-blind** | Wrong verdict, and the decisive evidence was never looked at. |

`right-by-accident` is the reason this exists. In a real queue it is
indistinguishable from competence until the day it isn't.

---

## Scenarios come in pairs

Every scenario has a twin that **fires the same rule and reaches the opposite
verdict**. The alert text is nearly word for word identical. Everything that
separates them is in the evidence.

```
identity-travel-tp   Impossible travel — Adelaide to Frankfurt in 22 minutes   true-positive
identity-travel-fp   Impossible travel — Adelaide to Frankfurt in 19 minutes   false-positive
```

In the first, the Frankfurt session is a new device reached after four denied
MFA pushes and one approval on the fifth. In the second, it is the same device
id one minute after a VPN tunnel came up, and two colleagues sign in from the
same address over the next quarter hour.

Both alerts say *impossible travel*. Both source addresses are in hosting ASNs
— because corporate VPN egress usually is. The ASN is a distractor in both.

A drill never shows you both halves of a pair. Recognising the format is not
the skill.

---

## What it looks like

```
  ALERT 1 of 3

  rule      IDP-0031 Impossible travel
  severity  HIGH
  technique T1078.004 (Valid Accounts: Cloud Accounts)

  Successful sign-in for j.tan@corp.example from Adelaide (AU) and
  Frankfurt (DE), 14,200 km apart, 22 minutes apart.

  EVIDENCE
  [ 8] okta   2026-06-19T09:02:00Z okta eventType=user.session.start ... city=Frankfurt
              asn="AS3320 Deutsche Telekom" device_id=D-8891
  [ 0] okta   2026-09-15T13:03:00Z okta eventType=user.session.start ... city=Adelaide
  [ 2] okta   2026-09-15T13:23:00Z okta eventType=...auth_via_mfa outcome=DENIED attempt="1 of 5"
  ...

  verdict [t]rue-positive / [f]alse-positive / [q]uit: t
  evidence: 5,6

  Right verdict, but not from the evidence that settles it.

  actual verdict   true-positive
  you missed       2, 3, 4, 7
```

Every log source is rendered in its own shape — Okta system log, Sysmon
process creation, Zeek `conn.log`, CloudTrail JSON, Linux `auth.log` — because
an analyst trained on a uniform pretty-printed table has learned something that
does not transfer to a real console.

The base64 in the PowerShell scenarios is real. Decode it the way you would at
work:

```bash
echo 'SQBFAFgAKABOAGUAdwAt...' | base64 -d | iconv -f UTF-16LE
```

---

## Install and use

```bash
git clone https://github.com/citizen204/noisefloor && cd noisefloor
python -m noisefloor drill -n 3          # no install needed
pip install -e .                          # optional: puts `noisefloor` on PATH
```

```bash
noisefloor drill -n 3                     # a mixed drill
noisefloor drill --tag cloud              # one domain
noisefloor drill --seed 4471              # reproduce an exact drill
noisefloor list -v                        # the library
noisefloor show identity-travel-fp --answer
```

`--seed` makes a drill reproducible, so two people can work the same set and
compare which evidence each of them cited.

Exit code is `0` only when every scenario passed on **both** verdict and
reasoning.

---

## The library

| Scenario pair | Sources | The trap |
|---|---|---|
| Impossible travel | Okta, Zeek | The hosting ASN. Corporate VPN egress lives in hosting space too, so the ASN tells you nothing on its own. |
| Encoded PowerShell | Sysmon, Zeek, EDR | `-ExecutionPolicy Bypass` and `-enc`. Both are normal for software distribution; they describe how a command was passed, not what it does. |
| Cloud access key from a new address | CloudTrail | `GetCallerIdentity`. As the first call of a session it is orientation; after a successful deploy it is a script logging what it ran as. Position matters. |

Each scenario also carries the action it expects afterwards, because "it's real"
and "here is what I did about it" are different pieces of work.

---

## Design notes

```
noisefloor/
  model.py      Event, Alert, Scenario, GroundTruth — validated on construction
  render.py     per-source log formats
  grade.py      the five diagnoses
  library/      the scenarios, as data
  cli.py        drill / list / show
```

`model.py` validates aggressively: an out-of-range evidence index, or an event
marked both decisive and distractor, raises at import time rather than during a
drill. The library's own consistency — every scenario has a twin, twins point at
each other, twins disagree — is checked when the package loads and again in CI.

The scenarios are the product. The code is deliberately small so that adding
one is writing evidence and a ground truth, not writing software.

**Limits.** Six scenarios in three pairs. The evidence is hand-written rather
than generated from a real telemetry capture, so it is realistic in shape but
not in volume — a real queue buries the decisive event among thousands, and
nothing here trains that. There is no timing pressure, and no cost to escalating.

---

## Why grade the reasoning

I built [ghast](https://github.com/citizen204/ghast), a taint-analysis scanner
for GitHub Actions, and ran it against ~1,800 workflow files. It found no
exploitable vulnerabilities and thirteen classes of false positive in itself.
One of them was a claim about GitHub's cache scoping that was simply false, and
120 passing tests could not have caught it, because every test encoded the same
wrong belief.

That is the same failure as `right-by-accident`: a green signal about the wrong
subject. A scanner that is confidently wrong gets muted. An analyst who is
confidently right for the wrong reason gets promoted, and then misses one.

## License

MIT.
