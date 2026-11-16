"""Single hook that every side-effecting egress path calls first (security review 7 H-5).

Runtime installs `guard` (epoch.assert_active): when this controller is a standby, fenced, or its DB epoch no longer equals the one it started with, the
guard raises epoch.NotActive and NOTHING leaves the process: no agent request or enrollment, no Proxmox/provider call, no notification, no promotion, no
SSH bootstrap. Code without a Runtime (CLI tools, unit tests of pure functions) has no guard installed and is unaffected."""
guard = None


def require() -> None:
    if guard is not None:
        guard()
