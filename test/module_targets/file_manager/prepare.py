"""Cache genuine, pinned File Manager sources before starting a test stack."""

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
import fcntl
import hashlib
import io
import json
import os
import subprocess
import tempfile
import urllib.parse
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parents[3]
DIRECTORY = Path(__file__).resolve().parent
CACHE = ROOT / "tmp/module-target-file-manager-sources"
MAX_FILE = 24_000_000


def download(url):
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(MAX_FILE + 1)
        if response.status != 200 or len(data) > MAX_FILE:
            raise ValueError("Source HTTP response exceeds its contract")
        return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical_archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(files):
            entry = zipfile.ZipInfo("wp-file-manager/" + name, (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, files[name])
    return output.getvalue()


class DirectoryLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attributes):
        if tag == "a":
            self.links.extend(value for key, value in attributes if key == "href")


def immutable_files(base):
    """Export only children of the pinned official SVN revision, four at once."""
    if not base.startswith("https://plugins.svn.wordpress.org/!svn/bc/"):
        raise ValueError("Unexpected immutable source origin")

    def fetch(path):
        url = urllib.parse.urljoin(base, urllib.parse.quote(path, safe="/"))
        if not url.startswith(base):
            raise ValueError("Source URL leaves its pinned revision")
        data = download(url)
        if path and not path.endswith("/"):
            return path, data
        parser = DirectoryLinks()
        parser.feed(data.decode("utf-8"))
        children = []
        for href in parser.links:
            if href == "../" or urllib.parse.urlsplit(href).scheme:
                continue
            child = path + urllib.parse.unquote(href)
            if child.startswith("/") or ".." in PurePosixPath(child).parts:
                raise ValueError("Source directory contains an unsafe path")
            children.append(child)
        return path, children

    files = {}
    visited = {""}
    with ThreadPoolExecutor(max_workers=4) as pool:
        pending = {pool.submit(fetch, "")}
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                path, value = future.result()
                if isinstance(value, list):
                    for child in value:
                        if child in visited:
                            raise ValueError("Duplicate source entry")
                        visited.add(child)
                        if len(visited) > 5000:
                            raise ValueError("Source tree exceeds its entry limit")
                        pending.add(pool.submit(fetch, child))
                else:
                    files[path] = value
                    if sum(map(len, files.values())) > 64_000_000:
                        raise ValueError("Source tree exceeds its byte limit")
    return files


def fixed_archive(release):
    # The current-download URL is mutable. Its exact checksum is a fast path;
    # the immutable revision remains usable after that URL changes releases.
    try:
        data = download(release["official_url"])
    except (OSError, ValueError):
        data = None
    if data is not None and digest(data) == release["official_archive_sha256"]:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            files = {}
            for entry in archive.infolist():
                if entry.is_dir():
                    continue
                path = PurePosixPath(entry.filename)
                if path.is_absolute() or ".." in path.parts or path.parts[0] != "wp-file-manager":
                    raise ValueError("Unsafe official plugin member")
                name = str(path.relative_to("wp-file-manager"))
                if name in files or entry.file_size > MAX_FILE:
                    raise ValueError("Invalid official plugin member")
                files[name] = archive.read(entry)
    else:
        files = immutable_files(release["immutable_source_base"])
    if len(files) != release["source_files"]:
        raise ValueError("Fixed plugin source file count differs")
    return canonical_archive(files)


def main():
    CACHE.mkdir(parents=True, exist_ok=True)
    lock_path = Path.home() / ".cache/metasploit-framework/module-target-tests.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        environment = dict(os.environ, DOCKER_CONTEXT="default", BUILDX_BUILDER="default")
        result = subprocess.run(["docker", "ps", "--all", "--quiet"], env=environment,
                                capture_output=True, text=True, check=True, timeout=30)
        if result.stdout.strip():
            raise RuntimeError("Finish existing containers before preparing plugin sources")
        catalog = json.loads((DIRECTORY / "releases.json").read_text())
        for version, release in catalog.items():
            destination = CACHE / (version + ".zip")
            if not destination.is_file() or digest(destination.read_bytes()) != release["sha256"]:
                data = fixed_archive(release) if "immutable_source_base" in release else download(release["url"])
                if len(data) != release["bytes"] or digest(data) != release["sha256"]:
                    raise ValueError("Pinned File Manager " + version + " archive differs")
                with tempfile.NamedTemporaryFile(dir=CACHE, prefix=version + ".", delete=False) as temporary:
                    temporary.write(data)
                    temporary_path = Path(temporary.name)
                try:
                    temporary_path.replace(destination)
                finally:
                    temporary_path.unlink(missing_ok=True)
            print(json.dumps({"version": version, "sha256": release["sha256"], "verified": True}))


if __name__ == "__main__":
    main()
