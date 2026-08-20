# CI/CD Container Release Gate

Deterministic FastAPI implementation of `POST /release-gate`, ready for Vercel.

## GitHub upload

Upload all files and the `.github/workflows/release-gate.yml` path to the root
of a public repository. The workflow must remain at that exact path.

## Vercel deployment

Import the repository into Vercel, use the **FastAPI** framework preset, keep
the root directory as `./`, and deploy with the default settings. Submit the
Vercel base URL without `/release-gate`.

## Required submission JSON

```json
{
  "serviceUrl": "https://YOUR-PROJECT.vercel.app",
  "workflowUrl": "https://github.com/YOUR-USERNAME/YOUR-REPOSITORY/actions/workflows/release-gate.yml"
}
```
