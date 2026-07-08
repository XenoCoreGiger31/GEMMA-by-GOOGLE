#!/usr/bin/env python3
import subprocess, sys, os, argparse

IMAGE = "halo-sandbox:latest"

def run(script_path, phase, target=None):
    script_path = os.path.abspath(script_path)
    name = os.path.basename(script_path)
    net = ["--network=none"] if phase == "test" else ["--network=slirp4netns"]
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
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("script")
    p.add_argument("--phase", choices=["test", "attack"], default="test")
    p.add_argument("--target", default=None)
    a = p.parse_args()
    r = run(a.script, a.phase, a.target)
    print("=== STDOUT ===\n" + r.stdout)
    print("=== STDERR ===\n" + r.stderr)
    print(f"=== EXIT {r.returncode} ===")
