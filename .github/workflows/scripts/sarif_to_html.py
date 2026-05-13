import json
import os
import glob
import html
from datetime import datetime


sarif_dir = os.environ.get("SARIF_DIR")
if not sarif_dir:
    raise SystemExit("SARIF_DIR environment variable not set")

github_server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
repository = os.environ.get("GITHUB_REPOSITORY", "Unknown Repository")
organization = os.environ.get("GITHUB_REPOSITORY_OWNER", "Unknown Organization")
github_ref =  os.environ.get("GITHUB_SHA") or os.environ.get("GITHUB_REF_NAME") or "main"

print(f"Looking for SARIF files in {sarif_dir}...")
files = glob.glob(os.path.join(sarif_dir, "*.sarif"))
if not files:
    raise SystemExit(f"No SARIF file found in {sarif_dir}")

sarif_file = files[0]
print(f"Processing {sarif_file}...")
with open(sarif_file, "r", encoding="utf-8") as f:
    data = json.load(f)


def map_security_severity(value):
    if value in (None, ""):
        return ""
    try:
        score = float(value)
    except (TypeError, ValueError):
        return ""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return ""


def pick_category(tags, rule_id):
    for tag in tags:
        lower_tag = tag.lower()
        if "external/cwe/" in lower_tag:
            return lower_tag.split("/")[-1].upper()
    if "/" in rule_id:
        return rule_id.split("/")[0]
    return rule_id or "Unknown"


def pick_alert_name(rule_meta, result_message, rule_id):
    return (
        rule_meta.get("name")
        or rule_meta.get("shortDescription")
        or result_message
        or rule_id
        or "Unknown alert"
    )


def build_github_blob_url(server_url, repo, ref, path, line=None):
    print(f"==>Building GitHub URL with server_url={server_url}, repo={repo}, ref={ref}, path={path}, line={line}")
    if not repo or repo == "Unknown Repository" or not path:
        return ""
    clean_path = path.lstrip("/")
    url = f"{server_url}/{repo}/blob/{ref}/{clean_path}"
    if line:
        url += f"#L{line}"
    return url


all_findings = []
severity_counts = {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
}

for run in data.get("runs", []):
    tool = run.get("tool", {})
    driver = tool.get("driver", {}) or {}

    rule_map = {}

    def collect_rules(rule_defs):
        for rule_def in rule_defs or []:
            rule_id = rule_def.get("id", "")
            if not rule_id:
                continue

            props = rule_def.get("properties", {}) or {}
            tags = props.get("tags", []) or []

            rule_map[rule_id] = {
                "name": props.get("name", ""),
                "shortDescription": (rule_def.get("shortDescription", {}) or {}).get("text", ""),
                "problemSeverity": props.get("problem.severity", ""),
                "defaultLevel": (rule_def.get("defaultConfiguration", {}) or {}).get("level", ""),
                "securitySeverityScore": props.get("security-severity", ""),
                "securitySeverity": map_security_severity(props.get("security-severity", "")),
                "tags": tags,
            }

    collect_rules(driver.get("rules", []))
    for ext in tool.get("extensions", []):
        collect_rules(ext.get("rules", []))

    print(f"Built rule map with {len(rule_map)} entries")

    for result in run.get("results", []):
        rule_id = result.get("ruleId", "")
        message = (result.get("message", {}) or {}).get("text", "")
        rule_meta = rule_map.get(rule_id, {})

        locs = result.get("locations", []) or []
        location = ""
        location_path = ""
        location_line = ""

        if locs:
            pl = locs[0].get("physicalLocation", {}) or {}
            location_path = (pl.get("artifactLocation", {}) or {}).get("uri", "")
            region = pl.get("region", {}) or {}
            location_line = region.get("startLine", "")
            location = f"{location_path}:{location_line}" if location_line else location_path

        github_url = build_github_blob_url(
            github_server_url,
            repository,
            github_ref,
            location_path,
            location_line,
        )

        security_severity = rule_meta.get("securitySeverity", "")
        if security_severity:
            severity_counts[security_severity] += 1

        finding = {
            "repository": repository,
            "severity": security_severity or rule_meta.get("problemSeverity") or result.get("level", "") or rule_meta.get("defaultLevel", "") or "unknown",
            "severity_class": security_severity,
            "category": pick_category(rule_meta.get("tags", []), rule_id),
            "alert_name": pick_alert_name(rule_meta, message, rule_id),
            "action_text": "View source" if github_url else "Review finding",
            "action_url": github_url,
            "location": location,
            "message": message,
            "rule_id": rule_id,
        }

        print(
            f"Found issue: rule={rule_id}, severity={finding['severity']}, "
            f"category={finding['category']}, location={location}, url={github_url}"
        )
        all_findings.append(finding)

total = len(all_findings)

rows = "\n".join(
    f"""<tr>
        <td>{html.escape(f["repository"])}</td>
        <td class="text-{html.escape(f["severity_class"])}">{html.escape(f["severity"].capitalize())}</td>
        <td>{html.escape(f["category"])}</td>
        <td title="{html.escape(f["message"])}">{html.escape(f["alert_name"])}</td>
        <td>{
            f'<a href="{html.escape(f["action_url"])}" target="_blank" rel="noopener noreferrer">{html.escape(f["action_text"])}</a>'
            if f["action_url"]
            else html.escape(f["action_text"])
        }</td>
    </tr>"""
    for f in all_findings
)

generated_time = datetime.now().strftime("%d-%m-%Y %I:%M %p")

out = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CodeQL Security Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; padding: 20px; background-color: #f4f4f4; }}
        .report-container {{ background-color: #fff; padding: 20px; border-radius: 8px; max-width: 1100px; margin: 0 auto; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #005cc5; margin-top: 0; }}
        .meta-info {{ color: #333; font-weight: bold; margin-bottom: 20px; line-height: 1.6; }}
        .summary-section {{ margin-bottom: 30px; }}
        .summary-cards {{ display: flex; justify-content: space-between; gap: 12px; background-color: #f8f9fa; padding: 15px; border-radius: 6px; flex-wrap: wrap; }}
        .card {{ text-align: center; flex: 1; min-width: 120px; }}
        .card-label {{ display: block; font-size: 14px; font-weight: 600; margin-bottom: 5px; }}
        .card-value {{ font-size: 18px; font-weight: bold; color: #333; }}
        .text-critical {{ color: #cb2431; }}
        .text-high {{ color: #d73a49; }}
        .text-medium {{ color: #b08800; }}
        .text-low {{ color: #0366d6; }}
        .pending-alerts h3 {{ margin-bottom: 10px; color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; background: white; }}
        thead th {{ background-color: #005cc5; color: white; padding: 12px; text-align: left; font-weight: 600; }}
        tbody td {{ border-bottom: 1px solid #e1e4e8; padding: 12px; vertical-align: top; color: #24292e; }}
        tbody tr:nth-child(even) {{ background-color: #fafbfc; }}
        .empty-state {{ color: #586069; padding: 20px 0; }}
        a {{ color: #0366d6; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>

<div class="report-container">
    <h1>CodeQL Security Report</h1>
    <div class="meta-info">
        <div>Organization: {html.escape(organization)}</div>
        <div>Repository: {html.escape(repository)}</div>
        <div>Date: {html.escape(generated_time)}</div>
    </div>

    <div class="summary-section">
        <h3>Summary</h3>
        <div class="summary-cards">
            <div class="card">
                <span class="card-label">Total</span>
                <span class="card-value">{total}</span>
            </div>
            <div class="card">
                <span class="card-label text-critical">Critical</span>
                <span class="card-value">{severity_counts["critical"]}</span>
            </div>
            <div class="card">
                <span class="card-label text-high">High</span>
                <span class="card-value">{severity_counts["high"]}</span>
            </div>
            <div class="card">
                <span class="card-label text-medium">Medium</span>
                <span class="card-value">{severity_counts["medium"]}</span>
            </div>
            <div class="card">
                <span class="card-label text-low">Low</span>
                <span class="card-value">{severity_counts["low"]}</span>
            </div>
        </div>
    </div>

    <div class="pending-alerts">
        <h3>Pending Alerts</h3>
        <table>
            <thead>
                <tr>
                    <th>Repository</th>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>Alert Name</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                {rows if rows else '<tr><td colspan="5" class="empty-state">No findings found.</td></tr>'}
            </tbody>
        </table>
    </div>
</div>

</body>
</html>"""

output_file = "codeql-security-report.html"
with open(output_file, "w", encoding="utf-8") as f:
    f.write(out)

print(f"Generated {output_file}")