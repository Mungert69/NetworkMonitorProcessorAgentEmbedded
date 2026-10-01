#!/usr/bin/env python3
"""Create the source-and-notices archive matching a firmware release."""

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import tarfile
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SUBMODULES = ("third_party/wolfssl", "third_party/yyjson")
COMPONENTS = ("espressif__brotli", "espressif__mqtt")


def run(*args, cwd=ROOT):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def export_git_tree(repo: pathlib.Path, destination: pathlib.Path, revision: str) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    archive = subprocess.Popen(
        ["git", "-C", str(repo), "archive", "--format=tar", revision], stdout=subprocess.PIPE
    )
    try:
        with tarfile.open(fileobj=archive.stdout, mode="r|*") as stream:
            stream.extractall(destination, filter="data")
    finally:
        archive.stdout.close()
    if archive.wait() != 0:
        raise RuntimeError(f"git archive failed for {repo}")


def verify_component(path: pathlib.Path) -> None:
    manifest_path = path / "CHECKSUMS.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for record in manifest["files"]:
        file_path = path / record["path"]
        if file_path.stat().st_size != record["size"]:
            raise ValueError(f"component file size mismatch: {file_path}")
        digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
        if digest != record["hash"]:
            raise ValueError(f"component checksum mismatch: {file_path}")


def package(version: str, sbom: pathlib.Path, output: pathlib.Path) -> pathlib.Path:
    if (ROOT / "firmware/version.txt").read_text(encoding="ascii").strip() != version:
        raise ValueError("requested version differs from firmware/version.txt")
    if run("git", "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("commit tracked source changes before packaging")
    if not sbom.is_file():
        raise FileNotFoundError(sbom)
    commit = run("git", "rev-parse", "HEAD")
    with tempfile.TemporaryDirectory(prefix="nm-source-") as temporary:
        root = pathlib.Path(temporary) / f"NetworkMonitorProcessorAgentEmbedded-{version}"
        root.mkdir()
        export_git_tree(ROOT, root, commit)
        # Avoid nesting previously created release archives in subsequent bundles.
        shutil.rmtree(root / "release-source", ignore_errors=True)
        for module in SUBMODULES:
            source = ROOT / module
            expected = run("git", "rev-parse", f"HEAD:{module}")
            actual = run("git", "-C", str(source), "rev-parse", "HEAD")
            if expected != actual:
                raise ValueError(f"submodule revision mismatch: {module}")
            export_git_tree(source, root / module, actual)
        for component in COMPONENTS:
            source = ROOT / "firmware/managed_components" / component
            if not source.is_dir():
                raise FileNotFoundError(f"resolved component source missing: {source}")
            verify_component(source)
            shutil.copytree(source, root / "third_party" / component,
                            ignore=shutil.ignore_patterns(".git", "__pycache__"))
        shutil.copy2(sbom, root / f"NetworkMonitorProcessorAgentEmbedded-{version}.cdx.json")
        submodule_lines = [f"{module}: {run('git', 'rev-parse', f'HEAD:{module}')}"
                           for module in SUBMODULES]
        manifest = [
            f"Firmware version: {version}",
            f"Project commit: {commit}",
            "ESP-IDF: v6.1, commit fff9895c82d744c7237be8847347bdd1b07c6643",
            *submodule_lines,
            "espressif/brotli: 1.2.0, verified against bundled CHECKSUMS.json",
            "espressif/mqtt: 1.1.0, verified against bundled CHECKSUMS.json",
            "See THIRD_PARTY_NOTICES.md for license terms and source locations.",
        ]
        (root / "SOURCE-MANIFEST.txt").write_text("\n".join(manifest) + "\n", encoding="utf-8")
        output.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(output, "w:gz", compresslevel=9) as archive:
            archive.add(root, arcname=root.name, recursive=True)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--sbom", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    result = package(args.version, args.sbom.resolve(strict=True), args.output.resolve())
    print(f"Created {result} ({result.stat().st_size} bytes)")
    print(f"SHA256 {hashlib.sha256(result.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
