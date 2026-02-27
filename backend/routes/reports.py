import os
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from sqlalchemy import select
from jinja2 import Environment, FileSystemLoader
from datetime import datetime, timezone

from database import async_session, Project, Scan, Finding
from config import TEMPLATE_DIR, REPORTS_DIR

router = APIRouter()

jinja_env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))


@router.get("/{project_id}")
async def generate_report(project_id: int):
    async with async_session() as session:
        project = await session.get(Project, project_id)
        if not project:
            raise HTTPException(404, "Project not found")

        result = await session.execute(
            select(Scan).where(Scan.project_id == project_id).order_by(Scan.started_at)
        )
        scans = result.scalars().all()

        all_findings = []
        for scan in scans:
            fr = await session.execute(select(Finding).where(Finding.scan_id == scan.id))
            all_findings.extend(fr.scalars().all())

    template = jinja_env.get_template("template.html")
    html = template.render(
        project_name=project.name,
        target=project.target,
        scope=project.scope,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        scans=[{
            "tool_name": s.tool_name,
            "command": s.command,
            "status": s.status,
            "output": s.output or "",
            "started_at": s.started_at.isoformat() if s.started_at else "",
            "finished_at": s.finished_at.isoformat() if s.finished_at else "",
        } for s in scans],
        findings=[{
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "evidence": f.evidence,
        } for f in all_findings],
        total_scans=len(scans),
        total_findings=len(all_findings),
    )

    filename = f"report_{project.name.replace(' ', '_')}_{project_id}.html"
    filepath = os.path.join(REPORTS_DIR, filename)
    with open(filepath, "w") as f:
        f.write(html)

    return HTMLResponse(content=html)


@router.get("/{project_id}/download")
async def download_report(project_id: int):
    async with async_session() as session:
        project = await session.get(Project, project_id)
        if not project:
            raise HTTPException(404, "Project not found")

    filename = f"report_{project.name.replace(' ', '_')}_{project_id}.html"
    filepath = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(filepath):
        await generate_report(project_id)
    return FileResponse(filepath, filename=filename, media_type="text/html")
