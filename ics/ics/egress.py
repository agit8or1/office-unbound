"""Single hook that every side-effecting egress path calls first (security review 7 H-5).

Runtime installs `guard` (epoch.assert_active): when this controller is a standby, fenced, or its DB epoch no longer equals the one it started with, the
guard raises epoch.NotActive and NOTHING leaves the process: no agent request or enrollment, no Proxmox/provider call, no notification, no promotion, no
SSH bootstrap. Code without a Runtime (CLI tools, unit tests of pure functions) has no guard installed and is unaffected."""
guard = None


def require() -> None:
    if guard is not None:
        guard()


identity = None       # Runtime installs a callable returning the headers that name this controller + its epoch (evidence at the far end)


def _request_hook(request) -> None:
    """httpx `request` event hook for every provider/notification client: ask the guard first (nothing is sent from a fenced/standby controller) and tell
    the far end WHICH controller at WHICH epoch is calling (X-OU-Controller / X-OU-Epoch: an external recorder can then prove who acted)."""
    require()
    if identity is not None:
        for k, v in identity().items():
            request.headers[k] = v


def hooks() -> dict:
    return {"request": [_request_hook]}
