"""
main_react.py — entry point for the ReAct agent

Usage:
  python -m src.main_react                                      # default: data/network_scan.xml
  python -m src.main_react data/scan1.xml                       # single scan
  python -m src.main_react data/scan1.xml data/scan2.xml ...    # multi-scan

Each scan file produces a separate Excel report in reports/.
"""
import os
import sys
from dotenv import load_dotenv

load_dotenv()


def main():
    # ── Collect scan files from CLI args ─────────────────────────────────────
    scan_files = sys.argv[1:] if len(sys.argv) > 1 else ["data/test2.xml"]

    # Validate all files exist before starting
    missing = [f for f in scan_files if not os.path.exists(f)]
    if missing:
        for f in missing:
            print(f"[!] Scan file not found: {f}")
        sys.exit(1)

    from src.modules.va_agent_react import VAAgentReAct
    from src.modules.reporter import RiskReporter

    model = os.getenv("VA_MODEL", "llama3.1:8b")
    print(f"[*] Model: {model}")
    print(f"[*] Scans: {', '.join(scan_files)}")

    # Single agent instance reused across all scans (KEV catalog loaded once)
    agent    = VAAgentReAct(model_name=model, verbose=True)
    reporter = RiskReporter()

    results = []

    for i, scan_file in enumerate(scan_files, 1):
        if len(scan_files) > 1:
            print(f"\n{'='*60}")
            print(f"[*] [{i}/{len(scan_files)}] Processing: {scan_file}")
            print(f"{'='*60}")

        findings, cve_sources, target = agent.run(scan_file)

        if findings:
            report_name = f"{target.replace('.', '_')}_react_assessment"
            path = reporter.save_report(report_name, findings, cve_sources)
            print(f"\n[+] Report saved: {path}")
            results.append((scan_file, target, path, True))
        else:
            print(f"[-] No findings produced for {scan_file}.")
            results.append((scan_file, "unknown", None, False))

    # ── Summary when processing multiple files ────────────────────────────────
    if len(scan_files) > 1:
        print(f"\n{'='*60}")
        print(f"[*] MULTI-SCAN SUMMARY — {len(scan_files)} files processed")
        print(f"{'='*60}")
        for scan_file, target, path, ok in results:
            status = f"✓  {path}" if ok else "✗  No findings"
            print(f"  {target:20s}  {status}")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    main()