"""LogSleuth CLI — analyze logs from the command line."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from .analyzer import analyze_logs


def main():
    parser = argparse.ArgumentParser(
        prog="logsleuth",
        description="LogSleuth — Cybersecurity Log Analyzer CLI",
    )
    parser.add_argument("file", type=str, help="Path to log file to analyze")
    parser.add_argument("--format", "-f", type=str, default=None,
                       help="Log format hint (auth_log, syslog, apache_access, nginx_access, jsonl, csv, generic)")
    parser.add_argument("--output", "-o", type=str, default=None,
                       help="Output file path (JSON). Prints to stdout if not specified.")
    parser.add_argument("--findings-only", action="store_true",
                       help="Output only findings, not full analysis")
    parser.add_argument("--severity", "-s", type=str, default=None,
                       help="Minimum severity filter (informational, low, medium, high, critical)")
    parser.add_argument("--iocs-only", action="store_true",
                       help="Output only extracted IOCs")
    
    args = parser.parse_args()
    
    # Read file
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Analyze
    result = analyze_logs(
        content=content,
        dataset_name=file_path.name,
        format_hint=args.format,
    )
    
    # Filter output
    if args.findings_only:
        output_data = [f.model_dump(mode="json") for f in result.findings]
        if args.severity:
            severity_order = ["informational", "low", "medium", "high", "critical"]
            min_idx = severity_order.index(args.severity.lower()) if args.severity.lower() in severity_order else 0
            output_data = [f for f in output_data if severity_order.index(f["severity"]) >= min_idx]
    elif args.iocs_only:
        output_data = [i.model_dump(mode="json") for i in result.iocs]
    else:
        output_data = result.model_dump(mode="json")
    
    # Output
    json_str = json.dumps(output_data, indent=2, default=str)
    
    if args.output:
        Path(args.output).write_text(json_str, encoding="utf-8")
        print(f"Results written to {args.output}", file=sys.stderr)
        
        # Print summary to stderr
        print(f"\n--- LogSleuth Analysis Summary ---", file=sys.stderr)
        print(f"File: {file_path.name}", file=sys.stderr)
        print(f"Format: {result.parse_result.format_detected}", file=sys.stderr)
        print(f"Lines: {result.parse_result.total_lines} total, {result.parse_result.parsed_count} parsed, {result.parse_result.error_count} errors", file=sys.stderr)
        print(f"Findings: {len(result.findings)}", file=sys.stderr)
        print(f"IOCs: {len(result.iocs)}", file=sys.stderr)
    else:
        print(json_str)


if __name__ == "__main__":
    main()
