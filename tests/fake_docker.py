"""A stand-in for the `docker` CLI whose containers are host directories.

`install` puts it first on PATH, so Harbor's real DockerEnvironment and nudi's host commands
run their own subprocess calls against it. A container's root is a directory. `exec` runs
the command on the host with the container paths /app, /tests, /logs and /nudi in its
arguments moved under the root, and the root in COPY_ROOT for the programs it runs. A bind
mount is a symlink. `commit` copies the root to an image that `compose up` can start. Each
compose command is logged in `compose.log`, one JSON list per line.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

CONTAINER_PATHS = re.compile(r"(?<![\w.$/-])/(app|tests|logs|nudi)(?=[/\s'\";]|$)")


def install(directory: Path, monkeypatch) -> Path:
    """Put the stand-in and a `python3` first on PATH; return its state directory."""
    bin_dir, state = directory / "bin", directory / "state"
    bin_dir.mkdir(parents=True)
    (state / "images").mkdir(parents=True)
    (state / "projects").mkdir()
    for name, command in (("docker", f'"{sys.executable}" "{Path(__file__).resolve()}"'), ("python3", f'"{sys.executable}"')):
        (bin_dir / name).write_text(f'#!/bin/sh\nexec {command} "$@"\n')
        (bin_dir / name).chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_DOCKER_STATE", str(state))
    return state


def image_id(name: str) -> str:
    return "sha256:" + hashlib.sha256(name.encode()).hexdigest()


def container_id(project: str) -> str:
    return hashlib.sha256(project.encode()).hexdigest()[:12]


class Docker:
    def __init__(self, state: Path):
        self.state = state

    def projects(self) -> dict[str, dict]:
        return {home.name: json.loads((home / "meta.json").read_text())
                for home in (self.state / "projects").iterdir() if (home / "meta.json").is_file()}

    def project_of(self, container: str) -> str:
        return next(name for name in self.projects() if container_id(name) == container)

    def run(self, args: list[str]) -> int:
        if args[0] == "compose":
            return self.compose(args[1:])
        if args[0] == "info":
            print("linux" if "{{.OSType}}" in args else "")
        elif args[:3] == ["inspect", "--format", "{{.Os}}"]:
            print("linux")
        elif args[0] == "inspect":
            meta = self.projects()[self.project_of(args[-1])]
            if "{{.Image}}" in args:
                print(image_id(meta["image"]))
            else:
                mounts = [{"Type": "bind", "Source": mount["source"], "Destination": mount["target"]} for mount in meta["mounts"]]
                print(json.dumps({"mounts": mounts, "tmpfs": None, "size": 0}))
        elif args[0] == "ps":
            project = next(arg for arg in args if arg.startswith("label=com.docker.compose.project=")).split("=", 2)[2]
            if project in self.projects():
                print(f"{container_id(project)}\t{project}-main-1" if "--format" in args else container_id(project))
        elif args[0] == "commit":
            container, tag = args[-2:]
            image = self.state / "images" / tag
            shutil.copytree(self.state / "projects" / self.project_of(container) / "root", image / "root", symlinks=True)
            (image / "changes.json").write_text(json.dumps([args[i + 1] for i, arg in enumerate(args) if arg == "--change"]))
            print(image_id(tag))
        elif args[:2] == ["image", "inspect"]:
            print("null")
        elif args[:2] == ["image", "ls"]:
            prefix = args[-1].removeprefix("reference=").removesuffix("*")
            for image in sorted((self.state / "images").glob(prefix + "*")):
                print(image.name)
        elif args[:2] == ["image", "rm"]:
            for tag in args[2:]:
                shutil.rmtree(self.state / "images" / tag)
        elif args[0] != "unpause":
            print(f"fake docker does not support {args}", file=sys.stderr)
            return 1
        return 0

    def compose(self, args: list[str]) -> int:
        project, files = None, []
        while args[0] in ("--project-name", "--project-directory", "-f"):
            flag, value, args = args[0], args[1], args[2:]
            if flag == "--project-name":
                project = value
            elif flag == "-f":
                files.append(Path(value))
        command, rest = args[0], args[1:]
        with (self.state / "compose.log").open("a") as log:
            log.write(json.dumps(args) + "\n")
        home = self.state / "projects" / project
        root = home / "root"
        if command == "down":
            shutil.rmtree(home, ignore_errors=True)
        elif command == "up":
            image = os.environ["PREBUILT_IMAGE_NAME"]
            source = self.state / "images" / image / "root"
            if source.is_dir():
                shutil.copytree(source, root, symlinks=True)
            else:
                root.mkdir(parents=True)
            mounts = [volume for file in files if file.name == "docker-compose-mounts.json"
                      for volume in json.loads(file.read_text())["services"]["main"]["volumes"]]
            for mount in mounts:
                link = root / mount["target"].lstrip("/")
                if link.is_symlink():
                    link.unlink()
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(mount["source"])
            (home / "meta.json").write_text(json.dumps({"image": image, "mounts": mounts}))
        elif command == "exec":
            return self.exec(root, rest)
        elif command == "cp":
            source, target = rest
            if target.startswith("main:"):
                destination = root / target.removeprefix("main:").lstrip("/")
                if source.endswith("/."):
                    shutil.copytree(source[:-2], destination, dirs_exist_ok=True)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy(source, destination)
            else:
                shutil.copy(root / source.removeprefix("main:").lstrip("/"), target)
        else:
            print(f"fake docker compose does not support {command}", file=sys.stderr)
            return 1
        return 0

    def exec(self, root: Path, args: list[str]) -> int:
        cwd, env = root, {**os.environ, "COPY_ROOT": str(root)}
        while args[0].startswith("-"):
            flag, args = args[0], args[1:]
            if flag in ("-w", "-e", "-u"):
                value, args = args[0], args[1:]
                if flag == "-w":
                    cwd = root / value.lstrip("/")
                elif flag == "-e":
                    key, _, setting = value.partition("=")
                    env[key] = setting
        argv = [CONTAINER_PATHS.sub(lambda match: f"{root}/{match.group(1)}", arg) for arg in args[1:]]
        return subprocess.run(argv, cwd=cwd if cwd.is_dir() else root, env=env).returncode


if __name__ == "__main__":
    sys.exit(Docker(Path(os.environ["FAKE_DOCKER_STATE"])).run(sys.argv[1:]))
