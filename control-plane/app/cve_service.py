"""
CVE Feed Service — fetches, parses, and evaluates CVE data against live cluster state.

Supported feed formats (auto-detected):
  - JSON Feed 1.0  : kubernetes.io official CVE feed
  - OSV            : Open Source Vulnerability format (osv.dev, GitHub Advisory)
  - NVD JSON 2.0   : NIST National Vulnerability Database
"""

import re
import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

import httpx
from sqlalchemy.orm import Session

from .models import CVEFeed, CVEEntry, CVEScanResult

logger = logging.getLogger(__name__)

# ── Version helpers ────────────────────────────────────────────────────────────

def _parse_semver(v: str) -> tuple:
    """Parse a semver string like '1.28.4' or 'v1.28.4' into (major, minor, patch)."""
    v = v.lstrip("v").strip()
    parts = re.split(r"[.\-+]", v)
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return (major, minor, patch)
    except (ValueError, IndexError):
        return (0, 0, 0)


def _version_in_range(version: str, introduced: str, fixed: Optional[str]) -> bool:
    """Return True if version >= introduced and (no fixed, or version < fixed)."""
    v = _parse_semver(version)
    intro = _parse_semver(introduced) if introduced and introduced != "0" else (0, 0, 0)
    if v < intro:
        return False
    if fixed:
        fix = _parse_semver(fixed)
        if v >= fix:
            return False
    return True


def _cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text or "").strip()


def _parse_iso(dt_str: Optional[str]) -> Optional[datetime]:
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, AttributeError):
        return None


# ── Format parsers ─────────────────────────────────────────────────────────────

def _parse_json_feed(data: dict, feed_id: UUID) -> list:
    """Parse JSON Feed 1.0 format — used by kubernetes.io official CVE feed."""
    entries = []
    for item in data.get("items", []):
        title = item.get("title", "")
        cve_match = re.search(r"CVE-\d{4}-\d+", title)
        cve_id = cve_match.group(0) if cve_match else re.sub(r"^https?://\S+/", "", item.get("id", "UNKNOWN"))

        content = _strip_html(item.get("content_html", item.get("content_text", "")))

        severity = "UNKNOWN"
        sev_match = re.search(r"\b(Critical|High|Medium|Low)\b", content, re.IGNORECASE)
        if sev_match:
            severity = sev_match.group(1).upper()

        cvss_score = None
        cvss_match = re.search(r"CVSS[^:]*?(?:Score)?[:\s]+([\d.]{3,4})", content, re.IGNORECASE)
        if cvss_match:
            try:
                cvss_score = float(cvss_match.group(1))
                if severity == "UNKNOWN":
                    severity = _cvss_to_severity(cvss_score)
            except ValueError:
                pass

        refs = []
        if item.get("url"):
            refs.append({"url": item["url"], "type": "ADVISORY"})
        for link in item.get("attachments", []):
            refs.append({"url": link.get("url", ""), "type": "WEB"})

        entries.append({
            "feed_id": feed_id,
            "cve_id": cve_id,
            "title": title[:500],
            "description": content[:2000],
            "severity": severity,
            "cvss_score": cvss_score,
            "affected_components": [],  # JSON Feed has no structured version data
            "fixed_in": None,
            "published_date": _parse_iso(item.get("date_published")),
            "modified_date": _parse_iso(item.get("date_modified")),
            "references": refs,
        })
    return entries


def _parse_osv(data: dict, feed_id: UUID) -> list:
    """Parse OSV (Open Source Vulnerability) format — osv.dev, GitHub Advisory DB."""
    raw_vulns = data.get("vulns", [])
    if not raw_vulns:
        # Single OSV object
        raw_vulns = [data] if "id" in data else []

    entries = []
    for vuln in raw_vulns:
        cve_id = vuln.get("id", "UNKNOWN")
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                cve_id = alias
                break

        # CVSS / severity
        cvss_score = None
        severity = "UNKNOWN"
        db_specific = vuln.get("database_specific", {})
        if "cvss" in db_specific:
            cvss_data = db_specific["cvss"]
            cvss_score = cvss_data.get("score")
            severity = cvss_data.get("severity", "UNKNOWN").upper()
        elif "severity" in db_specific:
            severity = str(db_specific["severity"]).upper()

        for sev_entry in vuln.get("severity", []):
            score_str = sev_entry.get("score", "")
            base_match = re.search(r"(\d+\.\d+)$", score_str)
            if base_match and cvss_score is None:
                try:
                    cvss_score = float(base_match.group(1))
                except ValueError:
                    pass

        if severity == "UNKNOWN" and cvss_score is not None:
            severity = _cvss_to_severity(float(cvss_score))

        # Affected components + version ranges
        affected_components = []
        fixed_versions = []
        for affected in vuln.get("affected", []):
            pkg = affected.get("package", {})
            ranges = []
            for r in affected.get("ranges", []):
                introduced, fixed = None, None
                for event in r.get("events", []):
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        fixed = event["fixed"]
                        fixed_versions.append(fixed)
                if introduced:
                    ranges.append({
                        "type": r.get("type", "SEMVER"),
                        "introduced": introduced,
                        "fixed": fixed,
                    })
            affected_components.append({
                "component": pkg.get("name", ""),
                "ecosystem": pkg.get("ecosystem", ""),
                "ranges": ranges,
                "versions": affected.get("versions", []),
            })

        refs = [{"url": r.get("url", ""), "type": r.get("type", "WEB")} for r in vuln.get("references", [])]

        entries.append({
            "feed_id": feed_id,
            "cve_id": cve_id,
            "title": vuln.get("summary", cve_id)[:500],
            "description": vuln.get("details", "")[:2000],
            "severity": severity,
            "cvss_score": float(cvss_score) if cvss_score is not None else None,
            "affected_components": affected_components,
            "fixed_in": list(set(fixed_versions)) or None,
            "published_date": _parse_iso(vuln.get("published")),
            "modified_date": _parse_iso(vuln.get("modified")),
            "references": refs,
        })
    return entries


def _parse_nvd(data: dict, feed_id: UUID) -> list:
    """Parse NVD JSON 2.0 format — nvd.nist.gov."""
    entries = []
    for wrapper in data.get("vulnerabilities", []):
        cve = wrapper.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            ""
        )

        cvss_score, severity = None, "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(key, [])
            if metrics:
                cvss_data = metrics[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
                break

        # CPE-based affected components
        affected_components = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    if not cpe.get("vulnerable"):
                        continue
                    parts = cpe.get("criteria", "").split(":")
                    component = parts[4] if len(parts) > 4 else "unknown"
                    ver_start = cpe.get("versionStartIncluding", "0")
                    ver_end = cpe.get("versionEndExcluding")
                    ranges = []
                    if ver_start or ver_end:
                        ranges.append({
                            "type": "SEMVER",
                            "introduced": ver_start or "0",
                            "fixed": ver_end,
                        })
                    affected_components.append({
                        "component": component,
                        "ecosystem": "NVD",
                        "ranges": ranges,
                        "versions": [],
                    })

        refs = [{"url": r.get("url", ""), "type": r.get("type", "WEB")} for r in cve.get("references", [])]

        entries.append({
            "feed_id": feed_id,
            "cve_id": cve_id,
            "title": f"{cve_id}: {desc[:100]}",
            "description": desc[:2000],
            "severity": severity,
            "cvss_score": float(cvss_score) if cvss_score is not None else None,
            "affected_components": affected_components,
            "fixed_in": None,
            "published_date": _parse_iso(cve.get("published")),
            "modified_date": _parse_iso(cve.get("lastModified")),
            "references": refs,
        })
    return entries


# ── Feed detection ─────────────────────────────────────────────────────────────

def _detect_and_parse(data: dict, feed_id: UUID) -> list:
    """Auto-detect feed format and dispatch to the right parser."""
    if "vulnerabilities" in data:
        return _parse_nvd(data, feed_id)
    if "vulns" in data or ("id" in data and "affected" in data and "references" in data):
        return _parse_osv(data, feed_id)
    if "items" in data:
        return _parse_json_feed(data, feed_id)
    logger.warning(f"Unrecognised feed format for feed_id={feed_id}; keys={list(data.keys())[:10]}")
    return []


# ── Main service ───────────────────────────────────────────────────────────────

class CVEFeedService:

    # ── Feed management ────────────────────────────────────────────────────────

    async def fetch_and_parse(self, feed: CVEFeed) -> list:
        """Fetch a feed URL and return parsed entry dicts."""
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.get(feed.url, headers={"Accept": "application/json, */*"})
            resp.raise_for_status()
            data = resp.json()
        return _detect_and_parse(data, feed.id)

    async def refresh_feed(self, feed_id: UUID, db: Session) -> dict:
        feed = db.query(CVEFeed).filter(CVEFeed.id == feed_id).first()
        if not feed:
            raise ValueError(f"Feed {feed_id} not found")

        try:
            entries = await self.fetch_and_parse(feed)
        except Exception as e:
            logger.error(f"Failed to fetch feed '{feed.name}': {e}")
            raise

        # Replace existing entries atomically
        db.query(CVEEntry).filter(CVEEntry.feed_id == feed_id).delete(synchronize_session=False)
        for entry_data in entries:
            db.add(CVEEntry(**entry_data))

        feed.last_fetched = datetime.utcnow()
        feed.entry_count = len(entries)
        db.commit()

        logger.info(f"Feed '{feed.name}' refreshed: {len(entries)} entries loaded.")
        return {"feed": feed.name, "entries_loaded": len(entries)}

    async def refresh_all_feeds(self, db: Session) -> list:
        feeds = db.query(CVEFeed).filter(CVEFeed.enabled == True).all()
        results = []
        for feed in feeds:
            try:
                result = await self.refresh_feed(feed.id, db)
                results.append(result)
            except Exception as e:
                logger.error(f"Feed '{feed.name}' refresh failed: {e}")
                results.append({"feed": feed.name, "error": str(e)})
        return results

    # ── Cluster scanning ───────────────────────────────────────────────────────

    def _collect_cluster_versions(self) -> tuple:
        """Return (server_version_str, set_of_all_versions_to_check)."""
        server_version = "unknown"
        all_versions: set = set()
        try:
            from .k8s_client import K8sClient
            k8s = K8sClient()
            info = k8s.v1.get_code()
            # e.g. major="1", minor="28+"
            major = re.sub(r"\D", "", info.major or "0")
            minor = re.sub(r"\D", "", info.minor or "0")
            git_ver = (info.git_version or "").lstrip("v").split("-")[0]
            server_version = git_ver if git_ver else f"{major}.{minor}"
            all_versions.add(server_version)

            # Also collect kubelet versions from nodes
            nodes = k8s.get_nodes()
            if isinstance(nodes, list):
                for node in nodes:
                    # k8s_client.get_nodes() returns {"name", "status", "version"}
                    kv = node.get("version", "").lstrip("v").split("-")[0]
                    if kv:
                        all_versions.add(kv)
        except Exception as e:
            logger.warning(f"Could not query cluster version: {e}")
        return server_version, all_versions

    def scan_cluster(self, db: Session) -> dict:
        """Compare all enabled CVE entries against the live cluster versions."""
        server_version, versions_to_check = self._collect_cluster_versions()

        entries = (
            db.query(CVEEntry)
            .join(CVEFeed)
            .filter(CVEFeed.enabled == True)
            .all()
        )

        findings = []
        for entry in entries:
            components = entry.affected_components or []
            matched_versions = set()

            for comp in components:
                for check_ver in versions_to_check:
                    # Match against explicit version list
                    if any(v.lstrip("v").split("-")[0] == check_ver for v in comp.get("versions", [])):
                        matched_versions.add(check_ver)
                        continue
                    # Match against semver ranges
                    for r in comp.get("ranges", []):
                        if _version_in_range(check_ver, r.get("introduced", "0"), r.get("fixed")):
                            matched_versions.add(check_ver)
                            break

            if matched_versions:
                findings.append({
                    "cve_id": entry.cve_id,
                    "title": entry.title,
                    "severity": entry.severity,
                    "cvss_score": entry.cvss_score,
                    "affected_cluster_versions": sorted(matched_versions),
                    "fixed_in": entry.fixed_in,
                    "description": (entry.description or "")[:400],
                    "references": (entry.references or [])[:3],
                })

        # Sort: CRITICAL → HIGH → MEDIUM → LOW → UNKNOWN, then by CVSS desc
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        findings.sort(key=lambda x: (sev_order.get(x["severity"], 4), -(x["cvss_score"] or 0)))

        result = CVEScanResult(
            cluster_version=server_version,
            node_versions=sorted(versions_to_check - {server_version}),
            total_cves_checked=len(entries),
            affected_count=len(findings),
            findings=findings,
            status="completed",
        )
        db.add(result)
        db.commit()

        return {
            "scanned_at": result.scanned_at.isoformat(),
            "cluster_version": server_version,
            "node_versions": sorted(versions_to_check - {server_version}),
            "total_cves_checked": len(entries),
            "affected_count": len(findings),
            "severity_breakdown": _severity_breakdown(findings),
            "findings": findings,
        }

    def get_latest_scan(self, db: Session) -> Optional[dict]:
        scan = db.query(CVEScanResult).order_by(CVEScanResult.scanned_at.desc()).first()
        if not scan:
            return None
        findings = scan.findings or []
        return {
            "scanned_at": scan.scanned_at.isoformat(),
            "cluster_version": scan.cluster_version,
            "node_versions": scan.node_versions or [],
            "total_cves_checked": scan.total_cves_checked,
            "affected_count": scan.affected_count,
            "severity_breakdown": _severity_breakdown(findings),
            "findings": findings,
            "status": scan.status,
        }


def _severity_breakdown(findings: list) -> dict:
    breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        breakdown[sev] = breakdown.get(sev, 0) + 1
    return breakdown


# Singleton
cve_service = CVEFeedService()
