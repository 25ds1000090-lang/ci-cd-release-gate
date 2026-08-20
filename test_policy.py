from copy import deepcopy

from policy import evaluate_release


SAFE = {
    "target": "production",
    "event": "push",
    "ref": "refs/heads/main",
    "workflow": {
        "trigger": "push",
        "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "environmentApproval": True,
        "actions": [
            {"owner": "actions", "name": "checkout", "ref": "v4"},
            {"owner": "vendor", "name": "scan", "ref": "0123456789abcdef0123456789abcdef01234567"},
        ],
    },
    "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "buildkit",
        "criticalVulnerabilities": 0,
        "digestPinned": True,
    },
}


def test_safe():
    assert evaluate_release(SAFE) == {"decision": "promote", "violations": []}


def test_all_failures_together():
    payload = deepcopy(SAFE)
    payload["event"] = "pull_request"
    payload["ref"] = "refs/heads/feature"
    payload["workflow"].update({
        "trigger": "pull_request_target",
        "permissions": {"contents": "write", "packages": "write", "id-token": "none", "issues": "write"},
        "testsPassed": False,
        "matrixComplete": False,
        "failFast": True,
        "environmentApproval": False,
        "actions": [{"owner": "third-party", "name": "build", "ref": "v1"}],
    })
    payload["image"].update({
        "multiStage": False,
        "runsAsRoot": True,
        "secretMode": "arg",
        "criticalVulnerabilities": 2,
        "digestPinned": False,
    })
    assert set(evaluate_release(payload)["violations"]) == {
        "EXCESS_PERMISSION", "UNSAFE_PR_TRIGGER", "TESTS_INCOMPLETE",
        "MUTABLE_ACTION", "SINGLE_STAGE_IMAGE", "ROOT_RUNTIME",
        "SECRET_IN_LAYER", "CRITICAL_CVE", "UNPINNED_IMAGE",
        "INVALID_PRODUCTION_REF", "APPROVAL_REQUIRED",
    }


if __name__ == "__main__":
    test_safe()
    test_all_failures_together()
    print("all release-gate tests passed")
