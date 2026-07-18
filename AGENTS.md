# AGENTS.md — conventions for AI coding agents

## Build / test / lint

Backend (Python FastAPI):
```bash
cd control-plane
pip install -r requirements.txt
KAAVAL_ADMIN_PASSWORD=test-admin-password pytest tests/
```

Frontend (Next.js):
```bash
cd dashboard
npm ci
npm run dev
```

## Conventions

- Backend codebase is located under `control-plane/app/`.
- Frontend dashboard is located under `dashboard/`.
- Keep `llms.txt` to a single Markdown H1. Avoid `# ` (hash-space) comment lines inside its code blocks — strict Markdown parsers count them as extra H1 headings.
