from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler

from .database import SessionLocal
from . import models, scanner

FREQUENCY_INTERVALS = {
    "every_5_min": timedelta(minutes=5),
    "daily": timedelta(days=1),
    "weekly": timedelta(weeks=1),
}


def run_due_scans():
    db = SessionLocal()
    try:
        assets = (
            db.query(models.Asset)
            .filter(models.Asset.scan_frequency != "disabled")
            .all()
        )

        for asset in assets:
            interval = FREQUENCY_INTERVALS.get(asset.scan_frequency)
            if interval is None:
                continue

            is_due = (
                asset.last_scanned_at is None
                or datetime.utcnow() - asset.last_scanned_at >= interval
            )

            if not is_due:
                continue

            print(f"[SCHEDULER] Running scheduled scan for asset {asset.id} ({asset.target})")

            try:
                findings_data = scanner.scan_target(asset.target)
            except ValueError:
                asset.last_scanned_at = datetime.utcnow()
                db.commit()
                continue

            highest_risk = scanner.summarize_risk(findings_data)

            scan_result = models.ScanResult(
                asset_id=asset.id,
                status="completed",
                open_ports_count=len(findings_data),
                highest_risk=highest_risk
            )
            db.add(scan_result)
            db.commit()
            db.refresh(scan_result)

            for f in findings_data:
                finding = models.ScanFinding(
                    scan_result_id=scan_result.id,
                    port=f["port"],
                    service=f["service"],
                    risk_level=f["risk_level"],
                    description=f["description"]
                )
                db.add(finding)

            high_risk_findings = [f for f in findings_data if f["risk_level"] == "high"]
            if high_risk_findings:
                ports_list = ", ".join(str(f["port"]) for f in high_risk_findings)
                alert = models.SecurityAlert(
                    asset_id=asset.id,
                    scan_result_id=scan_result.id,
                    message=f"[Scheduled scan] High-risk open port(s) detected on {asset.name} ({asset.target}): {ports_list}",
                    risk_level="high"
                )
                db.add(alert)

            asset.last_scanned_at = datetime.utcnow()
            db.commit()

    finally:
        db.close()


def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(run_due_scans, "interval", minutes=1)
    scheduler.start()
    return scheduler