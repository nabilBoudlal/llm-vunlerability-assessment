"""
react_parser.py — Pure parsing utilities for the ReAct loop.

All functions are stateless and have no side effects.
They parse raw LLM text into structured Python objects.

Functions:
  _try_parse_json(raw)         — robust JSON extraction with truncation recovery
  _parse_react_step(text)      — extract first action from a ReAct step
  _parse_all_actions(text)     — extract ALL actions from a single LLM response
  _valid_cve_year(cve_id, ver) — plausibility filter (8B model guardrail)
  _sanitize_findings(findings) — post-process LLM findings against tool cache
"""

import json
import re
import datetime

CURRENT_YEAR = datetime.datetime.now().year


# ── JSON parsing ───────────────────────────────────────────────────────────────

def _try_parse_json(raw: str) -> dict | None:
    """Try to parse JSON; if truncated, attempt partial recovery."""
    if not raw:
        return None

    # Strip markdown fences
    clean = re.sub(r"```(?:json)?|```", "", raw).strip()

    # Find outermost {...}
    start = clean.find("{")
    if start == -1:
        return None

    # Try full parse first
    end = clean.rfind("}") + 1
    if end > start:
        try:
            return json.loads(clean[start:end])
        except json.JSONDecodeError:
            pass

    # Attempt partial recovery for truncated responses
    body = clean[start:]
    depth = 0
    for i, ch in enumerate(body):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(body[:i+1])
                except json.JSONDecodeError:
                    break

    # Last resort: try to extract individual finding objects
    findings = []
    start2 = None
    depth2 = 0
    for i, ch in enumerate(body):
        if ch == "{":
            if depth2 == 0:
                start2 = i
            depth2 += 1
        elif ch == "}":
            depth2 -= 1
            if depth2 == 0 and start2 is not None:
                try:
                    f = json.loads(body[start2:i+1])
                    findings.append(f)
                except Exception:
                    pass
                start2 = None
    if findings:
        return {"findings": findings, "_truncated": True}
    return None


# ── ReAct step parsing ─────────────────────────────────────────────────────────

def _parse_react_step(text: str) -> tuple[str | None, str | None, dict | None, dict | None]:
    """
    Parse the FIRST action from a ReAct step (kept for compatibility).
    Returns (thought, action, action_input_dict, final_answer_dict)
    """
    actions = _parse_all_actions(text)
    thought = None
    # Also handle **Thought:** markdown variant emitted by 8B models
    tm = re.search(r'\*{0,2}Thought\*{0,2}\s*:\s*(.+?)(?=\*{0,2}Action\*{0,2}\s*:|$)',
                   text, re.DOTALL | re.IGNORECASE)
    if tm:
        thought = tm.group(1).strip()

    if not actions:
        return thought, None, None, None

    action, input_dict = actions[0]
    final_json = input_dict if action == "FINAL_ANSWER" else None
    return thought, action, input_dict, final_json


def _strip_md(text: str) -> str:
    """
    Normalize a LLM response by stripping markdown decorators that 8B local
    models emit despite being told not to.

    Handles two common patterns:
      **Action:**  input   →  Action: input     (asterisks wrap label+colon)
      **Action**:  input   →  Action: input     (asterisks wrap label only)
      ## Thought:  ...     →  Thought: ...      (header prefix)
    """
    # Remove leading markdown headers (##, ###, etc.)
    text = re.sub(r'^#{1,4}\s*', '', text, flags=re.MULTILINE)
    # Pattern 1: **Label:** — asterisks wrap "Label:" as a unit
    text = re.sub(r'\*{1,2}([\w][\w ]*?):\*{1,2}', r'\1:', text)
    # Pattern 2: **Label**: — asterisks wrap label, colon outside
    text = re.sub(r'\*{1,2}([\w][\w ]*?)\*{1,2}\s*:', r'\1:', text)
    # Same patterns with underscores
    text = re.sub(r'_{1,2}([\w][\w ]*?):_{1,2}', r'\1:', text)
    text = re.sub(r'_{1,2}([\w][\w ]*?)_{1,2}\s*:', r'\1:', text)
    return text


def _parse_all_actions(text: str) -> list[tuple[str, dict | None]]:
    """
    Extract ALL (action, input_dict) pairs from a single LLM response.

    The 8B model frequently emits multiple Action/Action Input blocks in one
    reply — executing all of them avoids silently dropping research steps.

    Handles markdown-decorated responses (8B local model quirk):
      **Action:** search_nvd  →  treated as  Action: search_nvd
      **Action Input:** {...} →  treated as  Action Input: {...}

    Also handles bare FINAL_ANSWER blocks (model omits 'Action:' prefix):
      **FINAL_ANSWER**  /  FINAL_ANSWER  followed by { ... }

    Returns list of (action_name, parsed_input_dict) in order of appearance.
    """
    results = []

    # Normalise markdown decorators before parsing
    clean = _strip_md(text)

    # ── 1. Standard "Action: ... / Action Input: {...}" blocks ────────────────
    # Split on every occurrence of "Action:" (but NOT "Action Input:")
    segments = re.split(r'(?=(?<!\w)Action\s*:(?!\s*Input))', clean,
                        flags=re.IGNORECASE)
    for seg in segments:
        # Match "Action: <name>" — name is one word (no spaces), stops at newline
        am = re.match(
            r'Action\s*:\s*([A-Za-z_][A-Za-z0-9_]*)[ \t]*(?:\n|Action\s*Input|$)',
            seg, re.IGNORECASE
        )
        if not am:
            continue
        action = am.group(1).strip()
        aim = re.search(r'Action\s*Input\s*:\s*(\{[\s\S]+)', seg, re.IGNORECASE)
        input_dict = _try_parse_json(aim.group(1)) if aim else None
        results.append((action, input_dict))

    # ── 2. Bare FINAL_ANSWER blocks (no "Action:" prefix) ────────────────────
    # Handles all variants the 8B model produces:
    #   **FINAL_ANSWER:**\n{...}
    #   **FINAL_ANSWER:**\n\n```\n{...}\n```   ← most common 8B pattern
    #   **FINAL_ANSWER:**\n```json\n{...}\n```
    #   FINAL_ANSWER:\n{...}
    if not any(a == "FINAL_ANSWER" for a, _ in results):
        # Pattern 1: **FINAL_ANSWER:** (colon inside asterisks) + optional fence
        bare = re.search(
            r'\*\*FINAL_ANSWER:\*\*\s*\n\s*(?:```[a-z]*\s*\n)?\s*(\{[\s\S]+)',
            text, re.IGNORECASE
        )
        # Pattern 2: **FINAL_ANSWER** : (colon outside) or plain FINAL_ANSWER:
        if not bare:
            bare = re.search(
                r'(?:\*{0,2}FINAL_ANSWER\*{0,2})\s*:\s*\n\s*(?:```[a-z]*\s*\n)?\s*(\{[\s\S]+)',
                text, re.IGNORECASE
            )
        if bare:
            input_dict = _try_parse_json(bare.group(1))
            if input_dict:
                results.append(("FINAL_ANSWER", input_dict))

    return results


# ── Post-processing guardrails ─────────────────────────────────────────────────

def _valid_cve_year(cve_id: str, version: str = "") -> bool:
    """
    MODEL-SIZE WORKAROUND (8B): reject temporally implausible CVEs.
    A CVE dated 1999 is unlikely to apply to software from 2020+.
    This guardrail is removable when upgrading to 70B+.
    """
    m = re.match(r'CVE-(\d{4})-', cve_id)
    if not m:
        return False
    year = int(m.group(1))
    if year < 1999 or year >= CURRENT_YEAR:
        return False
    vm = re.match(r'(\d+)\.', version or "")
    if vm:
        major = int(vm.group(1))
        era = (2019 if major >= 8 else
               2016 if major >= 7 else
               2012 if major >= 6 else
               2010 if major >= 5 else
               2009 if major >= 4 else 2005)
        if era >= 2015 and year < 2010:
            return False
    return True


def _sanitize_findings(findings: list, toolbox) -> list:
    """
    Apply lightweight post-processing to the LLM's final findings:
    - Verify CVE IDs exist in toolbox cache (tool-grounded)
    - Apply year plausibility filter (8B workaround)
    - Apply CVSS >= 9.0 → Critical override (data-driven)
    - Apply bindshell/backdoor → Critical override
    - Sort by severity
    """
    sanitized = []
    for f in findings:
        port    = str(f.get("port", "?"))
        service = f.get("service", "")
        sev     = f.get("severity", "Informational")
        version = service.split(" ", 1)[1] if " " in service else ""
        cves    = f.get("cves", [])

        # Only keep CVEs that came from an actual tool call
        verified = []
        removed  = []
        for cid in cves:
            if cid not in toolbox._cve_cache:
                removed.append(f"{cid}(not in cache)")
                continue
            if not _valid_cve_year(cid, version):
                removed.append(f"{cid}(year)")
                continue
            verified.append(cid)
        if removed:
            print(f"  [guardrail] Port {port}: removed {removed}")
        f["cves"] = verified

        # Rebuild cve_details from cache
        cve_details        = {}
        best_cvss          = 0.0
        has_exploit        = False
        actively_exploited = False

        for cid in verified:
            src = toolbox._cve_cache.get(cid, {})
            cve_details[cid] = {
                "cvss":               src.get("cvss", "N/A"),
                "description":        src.get("description", ""),
                "url":                src.get("url",
                                        f"https://nvd.nist.gov/vuln/detail/{cid}"),
                "has_exploit":        src.get("has_exploit", False),
                "actively_exploited": src.get("actively_exploited", False),
                "source":             src.get("source", "nvd"),
            }
            try:
                v = float(src.get("cvss") or 0)
                if v > best_cvss:
                    best_cvss = v
            except Exception:
                pass
            has_exploit        = has_exploit or src.get("has_exploit", False)
            actively_exploited = actively_exploited or src.get("actively_exploited", False)

        f["cve_details"]        = cve_details
        f["has_exploit"]        = has_exploit
        f["actively_exploited"] = actively_exploited

        # CVSS override (data-driven)
        if best_cvss >= 9.0 and sev != "Critical":
            print(f"  [override] Port {port}: {sev} → Critical (CVSS {best_cvss})")
            f["severity"] = "Critical"

        # Backdoor / bindshell override
        if any(kw in service.lower() for kw in
               ("bindshell", "root shell", "backdoor", "metasploitable")):
            if f["severity"] != "Critical":
                print(f"  [override] Port {port}: bindshell → Critical")
                f["severity"] = "Critical"

        sanitized.append(f)

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    sanitized.sort(key=lambda x: order.get(x.get("severity", "Informational"), 5))
    return sanitized