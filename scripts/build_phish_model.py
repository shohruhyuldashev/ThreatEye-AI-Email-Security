#!/usr/bin/env python3
"""
Build the ThreatEye phishing-analyst model.

What this actually does — and does not do
-----------------------------------------
This produces a **specialised derived model** in Ollama: a Modelfile that pins a base
model together with an expert system prompt distilled from `data/phishing_corpus.json`
(the MITRE-anchored technique library), decoding parameters tuned for classification,
and worked examples that lock the output schema and the 0-100 scoring scale.

It is **not** gradient fine-tuning. Training weights would need a GPU, a labelled
corpus of real phishing/ham mail, and hours of compute; done badly on a small model it
reliably makes classification *worse*. Prompt specialisation over a retrieved technique
library gets most of the benefit here, runs on CPU, is reproducible in seconds, and —
importantly — stays inspectable: you can read exactly what the model was told.

The deterministic half of detection lives in `framework/phish_corpus.py`, which matches
the same corpus without the model at all.

Usage
-----
    python3 scripts/build_phish_model.py                 # write Modelfile + ollama create
    python3 scripts/build_phish_model.py --dry-run       # just write the Modelfile
    python3 scripts/build_phish_model.py --base qwen2.5:3b --name threateye-phish:1.0
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "data" / "phishing_corpus.json"
MODELFILE = REPO / "data" / "Modelfile.threateye-phish"


def load_corpus() -> dict:
    if not CORPUS.exists():
        sys.exit(f"corpus not found at {CORPUS} — run scripts/build_phishing_corpus.py first")
    return json.load(open(CORPUS))


def distil_system_prompt(corpus: dict) -> str:
    """Compress the corpus into an expert brief the model can hold in context."""
    techniques = corpus["techniques"]
    lures = sorted({t["lure"] for t in techniques})
    evasions = sorted({t["evasion"] for t in techniques})
    brands = sorted({t["brand"] for t in techniques})
    attack_ids = sorted({t["attack_id"] for t in techniques})

    # Highest-severity pattern per lure, so the brief carries real ratings.
    worst: dict[str, dict] = {}
    for t in techniques:
        cur = worst.get(t["lure"])
        if cur is None or t["severity"] > cur["severity"]:
            worst[t["lure"]] = t
    top = sorted(worst.values(), key=lambda t: -t["severity"])[:18]

    lure_lines = "\n".join(
        f"- {t['lure']}: {t['name'].split(' impersonating ')[0]} (typical severity {t['severity']})"
        for t in top
    )
    ev_counts = Counter(t["evasion"] for t in techniques)
    ev_lines = "\n".join(f"- {e}" for e, _ in ev_counts.most_common())

    return f"""You are ThreatEye's security analyst: a senior SOC engineer specialised in
email/phishing defence, with working expertise in malware analysis, secure code review,
web/network security, MITRE ATT&CK and incident response.

When scoring an email you judge one message at a time and answer ONLY with JSON. You are
precise, sceptical, and you do not inflate scores for ordinary business mail.

KNOWLEDGE BASE
You have been specialised on a library of {len(techniques)} concrete phishing patterns,
anchored on {len(attack_ids)} MITRE ATT&CK techniques ({", ".join(attack_ids[:10])} …),
covering {len(lures)} pretext families, {len(brands)} impersonated brands, and
{len(evasions)} evasion techniques.

HIGHEST-RISK PRETEXTS
{lure_lines}

EVASION TECHNIQUES YOU RECOGNISE
{ev_lines}

HOW TO JUDGE
1. Authentication is deterministic evidence. SPF, DKIM and DMARC all failing means the
   sender domain is unauthenticated and unaligned — that is spoofing, not a quirk.
2. A lookalike or homoglyph domain of a known brand (0ffice365, micros0ft, paypa1) is
   near-conclusive when combined with any credential request.
3. Credential harvesting = a link or form asking for a password, MFA code or banking
   detail. Treat "enter your current password to verify" as hostile by default.
4. Payment-instruction changes (bank details, direct deposit, wire) are the highest-value
   fraud path; weight them heavily even when the mail is well written.
5. Legitimate mail fails checks too. A newsletter with dkim=none, an internal colleague,
   or a genuine vendor notice from its real domain is NOT phishing. Do not punish mail
   for being commercial, urgent, or badly written on its own.
6. If a corpus technique is supplied in the prompt, anchor your score near its severity
   and name it in your evidence.

SCORING SCALE — every score field is an integer 0-100, never 0-10:
  0-20   benign
  21-50  suspicious
  51-80  likely phishing
  81-100 confirmed phishing
A verdict you describe as "high risk" must carry a score of at least 75.

BROADER SECURITY EXPERTISE (use this when reasoning about a message's payload, links or
attachments, and when answering SOC-analyst questions outside strict email scoring):

- Malware & payloads: recognise malicious Office macros (AutoOpen/Document_Open, WScript.Shell,
  base64 in VBA), HTML smuggling (Blob + a[download]), LOLBins (mshta, rundll32, regsvr32,
  certutil -decode, bitsadmin, powershell -enc), and script droppers. Deobfuscate base64,
  hex, char-code and string-concat obfuscation to reveal intent before judging.
- Programming & code review: read Python, JavaScript, PowerShell, Bash, SQL and PHP. Spot
  command injection (os.system/eval/exec with user input), SQL injection (string-built
  queries), path traversal (../), SSRF, insecure deserialization (pickle/yaml.load), hardcoded
  secrets, and weak crypto (MD5/SHA1 for passwords, ECB, static IVs). Explain the fix.
- Web & network: OWASP Top 10 (XSS, IDOR, CSRF, auth bypass), TLS/DNS/SPF-DKIM-DMARC mechanics,
  common CVE shapes, and how a phishing link chains into credential theft or a drive-by.
- ATT&CK & IR: map activity to MITRE ATT&CK tactics/techniques; outline containment,
  eradication and recovery steps; derive IOCs (domains, hashes, URLs) an analyst can block.
- Cryptography: hashing vs encryption, salting, HMAC, JWT alg-confusion/none, and why
  "encode" is not "encrypt".
Be accurate and concrete; if unsure, say so rather than inventing a CVE or command.

OUTPUT MODE:
- For email analysis (a message is given to score): answer ONLY with the JSON object
  requested — no prose before or after it.
- For a direct analyst question (no scoring requested): answer in clear, concise prose."""


def worked_examples() -> list[tuple[str, str]]:
    """Few-shot pairs that lock the schema, the scale, and the false-positive boundary."""
    hostile_out = json.dumps({
        "llm_score": 92, "confidence_score": 88,
        "explanation": "Lookalike domain 0ffice365-reset.com impersonating Microsoft 365 with a password-expiry pretext; SPF, DKIM and DMARC all fail; the body asks for the current password.",
        "threat_type": "Credential Phishing",
        "recommended_action": "Quarantine and reset the recipient's credentials if the link was opened.",
        "agent_verdicts": {
            "url_analyst": {"score": 94, "verdict": "Homoglyph lookalike of office365 on a newly registered domain"},
            "content_analyst": {"score": 90, "verdict": "Password-expiry urgency with an explicit credential request"},
            "prompt_guard": {"score": 5, "verdict": "No adversarial text aimed at the scanner"},
            "soc_verdict": {"score": 92, "verdict": "Confirmed credential phishing; quarantine"},
        },
        "evidence": ["homoglyph domain of office365", "SPF/DKIM/DMARC all fail", "asks for current password"],
    }, separators=(",", ":"))

    benign_out = json.dumps({
        "llm_score": 8, "confidence_score": 82,
        "explanation": "Vendor release-notes newsletter from the vendor's real domain. dkim=none is common for bulk senders and there is no credential request.",
        "threat_type": "Safe",
        "recommended_action": "Deliver.",
        "agent_verdicts": {
            "url_analyst": {"score": 6, "verdict": "Link points to the vendor's genuine domain"},
            "content_analyst": {"score": 10, "verdict": "Product announcement, no social engineering"},
            "prompt_guard": {"score": 2, "verdict": "Nothing adversarial"},
            "soc_verdict": {"score": 8, "verdict": "Benign bulk mail; deliver"},
        },
        "evidence": ["sender domain matches the brand", "no credential request", "bulk newsletter pattern"],
    }, separators=(",", ":"))

    return [
        ("Sender: it-helpdesk@0ffice365-reset.com | spf=fail dkim=fail dmarc=fail | Subject: Action required: password reset | Body: Reset at http://0ffice365-reset.com/reset now or lose access. Enter your current password to verify.", hostile_out),
        ("Sender: news@atlassian.com | spf=pass dkim=none dmarc=none | Subject: Jira 9.4 release notes | Body: This release adds sprint automation. Read more at https://atlassian.com/blog/jira-94", benign_out),
    ]


def render_modelfile(base: str, system: str, examples: list[tuple[str, str]]) -> str:
    lines = [
        f"FROM {base}",
        "",
        "# Near-deterministic: this is a classifier, not a creative writer. Sampling noise",
        "# here shows up as the same email scoring 30 one minute and 85 the next.",
        "PARAMETER temperature 0.1",
        "PARAMETER top_p 0.9",
        "PARAMETER repeat_penalty 1.05",
        # 4096 comfortably fits the system brief (~900 tok) + two few-shot examples
        # (~600 tok) + the per-email analyst prompt (~900 tok). A larger window just
        # makes every CPU inference slower for context this classifier never uses —
        # 8192 roughly doubled latency (~68s vs ~35s) for no accuracy gain.
        "PARAMETER num_ctx 4096",
        # Cap the JSON verdict; it never needs more and unbounded generation is the
        # other thing that stretches a CPU call.
        "PARAMETER num_predict 512",
        "",
        'SYSTEM """',
        system,
        '"""',
        "",
    ]
    for user, assistant in examples:
        lines += [f'MESSAGE user """{user}"""', f'MESSAGE assistant """{assistant}"""', ""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="qwen2.5:3b")
    ap.add_argument("--name", default="threateye-phish:1.1")
    ap.add_argument("--container", default="ollama", help="ollama container name")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    corpus = load_corpus()
    system = distil_system_prompt(corpus)
    content = render_modelfile(args.base, system, worked_examples())

    MODELFILE.parent.mkdir(parents=True, exist_ok=True)
    MODELFILE.write_text(content)
    print(f"Modelfile written: {MODELFILE}  ({len(content)} bytes)")
    print(f"  base           : {args.base}")
    print(f"  system prompt  : {len(system)} chars distilled from {len(corpus['techniques'])} techniques")

    if args.dry_run:
        return 0

    # The ollama container has the base model cached in its volume; build there.
    dest = "/root/.ollama/Modelfile.threateye-phish"
    print(f"copying Modelfile into container '{args.container}' …")
    subprocess.run(["docker", "cp", str(MODELFILE), f"{args.container}:{dest}"], check=True)
    print(f"creating model '{args.name}' …")
    r = subprocess.run(["docker", "exec", args.container, "ollama", "create", args.name, "-f", dest])
    if r.returncode != 0:
        return r.returncode
    subprocess.run(["docker", "exec", args.container, "ollama", "list"])
    print(f"\nDone. Point Settings → AI Engine at model: {args.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
