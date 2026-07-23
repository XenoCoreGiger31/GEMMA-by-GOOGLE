#!/usr/bin/env python3
import subprocess, sys, os, argparse

IMAGE = "halo-sandbox:latest"

# Wall-clock bound for a single sandboxed PoC. A hung script (e.g. a model-authored
# one that connect()s and blocks with no socket timeout) is killed at this bound and
# reported as a clean timeout — WITH a contract marker — instead of stalling the
# engagement and surfacing the opaque "No EXIT marker from sandbox". Env-overridable.
DEFAULT_TIMEOUT = int(os.environ.get("HALO_SANDBOX_TIMEOUT", "60"))


def build_cmd(script_path, phase, target=None):
    """Assemble the hardened `podman run` command for one PoC.

    TEST phase: no network at all — the script self-checks its own logic.
    ATTACK phase: shares the host netns (default) so the container routes to the LAN
    target exactly like the host's own tools; override with HALO_ATTACK_NET. Untrusted
    PoC isolation is still enforced by --read-only, --cap-drop=ALL, --pids-limit,
    --memory and --rm; only the network namespace is shared.
    """
    script_path = os.path.abspath(script_path)
    name = os.path.basename(script_path)
    attack_net = os.environ.get("HALO_ATTACK_NET", "host")
    net = ["--network=none"] if phase == "test" else [f"--network={attack_net}"]
    cmd = [
        "podman", "run", "--rm",
        "--read-only",
        "--cap-drop=ALL",
        "--memory=512m", "--cpus=1",
        "--pids-limit=128",
        *net,
        "-v", f"{script_path}:/work/{name}:ro",
    ]
    if target:
        cmd += ["-e", f"TARGET={target}"]
    cmd += [IMAGE, f"/work/{name}"]
    return cmd


def _text(v):
    """Coerce subprocess output (str | bytes | None) to str."""
    if v is None:
        return ""
    return v.decode("utf-8", "replace") if isinstance(v, bytes) else v


def run(script_path, phase, target=None, timeout=None, _runner=subprocess.run):
    """Run the PoC in the sandbox; return (stdout, stderr, returncode).

    A script that exceeds `timeout` is killed and reported as exit 124 (the shell
    timeout convention) with whatever partial output was captured — so the caller
    ALWAYS gets a parseable contract, never a crash with no marker. `_runner` is
    injectable so this is testable without podman."""
    timeout = DEFAULT_TIMEOUT if timeout is None else timeout
    cmd = build_cmd(script_path, phase, target)
    try:
        r = _runner(cmd, capture_output=True, text=True, timeout=timeout)
        return _text(r.stdout), _text(r.stderr), r.returncode
    except subprocess.TimeoutExpired as e:
        err = _text(e.stderr) + f"\n[sandbox] PoC exceeded {timeout}s wall-clock — killed"
        return _text(e.stdout), err, 124


def format_contract(stdout, stderr, returncode):
    """The exact STDOUT/STDERR/EXIT contract that _run_exploit parses."""
    return (f"=== STDOUT ===\n{stdout}\n"
            f"=== STDERR ===\n{stderr}\n"
            f"=== EXIT {returncode} ===")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("script")
    p.add_argument("--phase", choices=["test", "attack"], default="test")
    p.add_argument("--target", default=None)
    a = p.parse_args()
    out, err, rc = run(a.script, a.phase, a.target)
    print(format_contract(out, err, rc))
