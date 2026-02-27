from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from database import async_session, Project

router = APIRouter()


class ProjectCreate(BaseModel):
    name: str
    target: str
    scope: str = ""


class ProjectOut(BaseModel):
    id: int
    name: str
    target: str
    scope: str
    created_at: str

    class Config:
        from_attributes = True


@router.post("", response_model=ProjectOut)
async def create_project(data: ProjectCreate):
    async with async_session() as session:
        proj = Project(name=data.name, target=data.target, scope=data.scope)
        session.add(proj)
        await session.commit()
        await session.refresh(proj)
        return ProjectOut(
            id=proj.id, name=proj.name, target=proj.target,
            scope=proj.scope, created_at=proj.created_at.isoformat()
        )


@router.get("")
async def list_projects():
    async with async_session() as session:
        result = await session.execute(select(Project).order_by(Project.created_at.desc()))
        projects = result.scalars().all()
        return [
            {"id": p.id, "name": p.name, "target": p.target, "scope": p.scope, "created_at": p.created_at.isoformat()}
            for p in projects
        ]


@router.get("/{project_id}")
async def get_project(project_id: int):
    async with async_session() as session:
        proj = await session.get(Project, project_id)
        if not proj:
            raise HTTPException(404, "Project not found")
        return {"id": proj.id, "name": proj.name, "target": proj.target, "scope": proj.scope, "created_at": proj.created_at.isoformat()}


@router.delete("/{project_id}")
async def delete_project(project_id: int):
    async with async_session() as session:
        proj = await session.get(Project, project_id)
        if not proj:
            raise HTTPException(404, "Project not found")
        await session.delete(proj)
        await session.commit()
        return {"ok": True}
