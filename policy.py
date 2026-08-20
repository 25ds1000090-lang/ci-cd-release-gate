import re
from typing import Any


FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}


def evaluate_release(body: Any) -> dict[str, Any]:
    violations: list[str] = []
    request = body if isinstance(body, dict) else {}
    workflow = request.get("workflow")
    image = request.get("image")
    workflow = workflow if isinstance(workflow, dict) else {}
    image = image if isinstance(image, dict) else {}

    # 1. Exact least-privilege permissions; extra scopes are violations.
    if workflow.get("permissions") != REQUIRED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # 2. Pull requests must use the safe trigger.
    if request.get("event") == "pull_request" and workflow.get("trigger") != "pull_request":
        violations.append("UNSAFE_PR_TRIGGER")

    # Tests are required for every release candidate.
    if not (
        workflow.get("testsPassed") is True
        and workflow.get("matrixComplete") is True
        and workflow.get("failFast") is False
    ):
        violations.append("TESTS_INCOMPLETE")

    # 3. Only actions/* may use mutable version tags.
    actions = workflow.get("actions")
    mutable_action = not isinstance(actions, list)
    if isinstance(actions, list):
        for action in actions:
            if not isinstance(action, dict):
                mutable_action = True
                break
            owner = action.get("owner")
            ref = action.get("ref")
            if not isinstance(owner, str) or not isinstance(ref, str):
                mutable_action = True
                break
            if owner != "actions" and FULL_SHA.fullmatch(ref) is None:
                mutable_action = True
                break
    if mutable_action:
        violations.append("MUTABLE_ACTION")

    # 4. Hardened container-image requirements.
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")
    if image.get("secretMode") not in {"none", "buildkit"}:
        violations.append("SECRET_IN_LAYER")

    critical = image.get("criticalVulnerabilities")
    if isinstance(critical, bool) or not isinstance(critical, int) or critical != 0:
        violations.append("CRITICAL_CVE")
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 5. Additional production protections.
    if request.get("target") == "production":
        if request.get("event") != "push" or request.get("ref") != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")
        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }
