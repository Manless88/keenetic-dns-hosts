from __future__ import annotations

import io
import gzip
import re
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out"
PACKAGE = "keenetic-dns-hosts"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


DATA_FILES = [
    ("VERSION", f"/opt/share/{PACKAGE}/VERSION", 0o644),
    ("server.py", f"/opt/share/{PACKAGE}/server.py", 0o644),
    ("web/index.html", f"/opt/share/{PACKAGE}/web/index.html", 0o644),
    ("web/app.js", f"/opt/share/{PACKAGE}/web/app.js", 0o644),
    ("web/styles.css", f"/opt/share/{PACKAGE}/web/styles.css", 0o644),
    ("entware/S89keenetic-dns-hosts", "/opt/etc/init.d/S89keenetic-dns-hosts", 0o755),
    ("entware/keenetic-dns-hosts.conf.example", "/opt/etc/keenetic-dns-hosts.conf.example", 0o600),
]

CONTROL_FILES = [
    ("entware/package.control", "control", 0o644),
    ("entware/postinst", "postinst", 0o755),
    ("entware/prerm", "prerm", 0o755),
]


def tar_gz(files: list[tuple[str, str, int]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as tar:
        dirs = {"."}
        for _, target, _ in files:
            parts = target.lstrip("/").split("/")[:-1]
            current = "."
            for part in parts:
                current = f"{current}/{part}"
                dirs.add(current)
        for dirname in sorted(dirs):
            info = tarfile.TarInfo(dirname)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.mtime = 0
            tar.addfile(info)
        for source, target, mode in files:
            data = (ROOT / source).read_bytes()
            if target == "control":
                data = reversion_control(data)
            member_name = target.lstrip("/")
            if target.startswith("/"):
                member_name = f"./{member_name}"
            info = tarfile.TarInfo(member_name)
            info.size = len(data)
            info.mode = mode
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
    return output.getvalue()


def reversion_control(data: bytes) -> bytes:
    text = data.decode("utf-8")
    text = re.sub(r"^Version: .*$", f"Version: {VERSION}", text, flags=re.MULTILINE)
    return text.encode("utf-8")


def build() -> Path:
    OUT.mkdir(exist_ok=True)
    output = OUT / f"{PACKAGE}_{VERSION}.ipk"
    control = tar_gz(CONTROL_FILES)
    data = tar_gz(DATA_FILES)
    with tarfile.open(output, mode="w:gz") as tar:
        for name, content in (
            ("./debian-binary", b"2.0\n"),
            ("./data.tar.gz", data),
            ("./control.tar.gz", control),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o644
            info.mtime = 0
            tar.addfile(info, io.BytesIO(content))
    gz_output = output.with_suffix(output.suffix + ".gz")
    with output.open("rb") as source, gz_output.open("wb") as raw_target:
        with gzip.GzipFile(fileobj=raw_target, mode="wb", mtime=0) as target:
            target.write(source.read())
    return output


if __name__ == "__main__":
    print(build())
