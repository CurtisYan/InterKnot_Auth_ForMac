#!/usr/bin/env python3
"""Publish a prepared release using the project's macOS Keychain credential.

No token is written to disk, arguments or output. Existing public releases and
mismatching assets are never overwritten. Failed uploads leave a draft.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

API = "https://api.github.com/repos/CurtisYan/InterKnot_Auth_ForMac"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True, help="Full commit SHA already pushed to GitHub")
    parser.add_argument("--asset", type=Path, required=True)
    parser.add_argument("--notes", type=Path, required=True)
    args = parser.parse_args()
    if len(args.commit) != 40 or any(c not in "0123456789abcdef" for c in args.commit):
        parser.error("--commit must be a full 40-character lowercase SHA")
    asset_data = args.asset.read_bytes()
    digest = "sha256:" + hashlib.sha256(asset_data).hexdigest()
    notes = args.notes.read_text(encoding="utf-8")
    credential = subprocess.run(
        ["security", "find-generic-password", "-a", "github-release", "-s", "InterKnotAuthReleaseToken", "-w"],
        capture_output=True, text=True,
    )
    if credential.returncode or not credential.stdout.strip():
        raise RuntimeError("无法读取 InterKnotAuthReleaseToken；未发布 Release")
    token = credential.stdout.strip()

    def api(method, url, payload=None, raw=None):
        headers = {
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "InterKnotReleaseScript",
        }
        if payload is not None:
            raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif raw is not None:
            headers["Content-Type"] = "application/zip"
        try:
            with urlopen(Request(url, data=raw, headers=headers, method=method), timeout=60) as response:
                data = response.read()
                return json.loads(data) if data else None
        except HTTPError as error:
            try:
                detail = json.loads(error.read())
                safe_detail = {k: detail[k] for k in ("message", "errors") if k in detail}
            except (ValueError, TypeError):
                safe_detail = {}
            raise RuntimeError(f"GitHub API HTTP {error.code}: {json.dumps(safe_detail, ensure_ascii=False)}") from None

    # Read-only preflight: ensure the requested tag resolves to the intended commit.
    ref = api("GET", API + "/git/ref/tags/" + args.tag)
    obj = ref["object"]
    while obj["type"] == "tag":
        obj = api("GET", obj["url"])["object"]
    if obj["type"] != "commit" or obj["sha"] != args.commit:
        raise RuntimeError("远端 tag 与待发布提交不一致；未创建 Release")

    releases = api("GET", API + "/releases?per_page=100")
    release = next((item for item in releases if item["tag_name"] == args.tag), None)
    if release is None:
        release = api("POST", API + "/releases", {
            "tag_name": args.tag, "target_commitish": args.commit,
            "name": "InterKnotAuth " + args.tag, "body": notes, "draft": True, "prerelease": False,
        })
        print("已创建 Release 草稿", flush=True)

    assets = api("GET", release["assets_url"])
    asset = next((item for item in assets if item["name"] == args.asset.name), None)
    if not release["draft"] and asset is None:
        raise RuntimeError("Release 已公开发布但附件不同；停止以避免修改已有发布")
    if asset is None:
        upload = release["upload_url"].split("{")[0] + "?" + urlencode({"name": args.asset.name})
        asset = api("POST", upload, raw=asset_data)
        print("安装包已上传", flush=True)
    if asset.get("state") != "uploaded" or asset["size"] != len(asset_data) or asset.get("digest") != digest:
        raise RuntimeError("附件大小或 SHA-256 校验失败；不发布草稿、不覆盖原附件")
    if release["draft"]:
        release = api("PATCH", release["url"], {
            "name": "InterKnotAuth " + args.tag, "body": notes,
            "draft": False, "prerelease": False, "make_latest": "true",
        })
    verified = api("GET", API + "/releases/tags/" + args.tag)
    verified_asset = next(a for a in verified["assets"] if a["name"] == args.asset.name)
    if verified["draft"] or verified_asset.get("digest") != digest:
        raise RuntimeError("发布后校验未通过")
    print(json.dumps({"release": verified["html_url"], "asset": verified_asset["browser_download_url"],
                      "sha256": digest, "size": verified_asset["size"]}, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, KeyError, StopIteration) as error:
        raise SystemExit(str(error)) from None
