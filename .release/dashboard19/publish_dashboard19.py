"""Exact signed .19 dashboard publication. GitHub-hosted runner only; no signer or private key."""
import base64
import hashlib
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

REPO = "jgohdapt/noranjip-updates"
ROOT = ".release/dashboard19/"
TAG = "dashboard-v2-0.1.19"
STABLE_TAG = "dashboard-v2-stable"
STABLE_ID = 387535340
OLD_ID = 622044209
OLD_NAME = "dashboard-manifest-0.1.18.xml"
FIXED_NAME = "dashboard-manifest.xml"
STAGE_NAME = "dashboard-manifest-0.1.19.xml"
ZIP_NAME = "dashboard.exe"
ZIP_SHA = NEW_SHA = FROZEN_INPUTS_SHA = None
ZIP_BYTES = None
OLD_SHA = "17BAF24D3CA2F6C5FE45EEC5FC098961E59488E9848D291E608423344CF718A8"
ARCHIVE_ID = 594643022
ARCHIVE_NAME = "dashboard-manifest-0.2.3.33.xml"
ARCHIVE_SHA = "BF239763435D3A276B14206798E965E33839783673ACE9A82E5981E97B39EF39"
LATEST_ID = 385231275
LATEST_TAG = "stable-20260909-01"
PUBLIC_KEY_SHA = "D6245B3479BF7A997386F1A2BD4530FCA3887B5523A70B46191185E60CC90BA1"
ARCHIVE36_ID = 602903912
ARCHIVE36_NAME = "dashboard-manifest-0.2.3.36.xml"
ARCHIVE36_SHA = "07CB345B7B075920CE8F02CF515D724FA1C7EF8869E81F46FA68CE13679204C2"
ARCHIVE35_ID = 602344613
ARCHIVE35_NAME = "dashboard-manifest-0.2.3.35.xml"
ARCHIVE35_SHA = "2AA6E6CF97BC29428FF26ED685F2FEFCE8B0380AD920C7A5AD2F30A6E0229BEF"
FILE_NAMES = {"dashboard.exe"}
FILES = None


class Refused(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Refused(code)


def digest(data):
    return hashlib.sha256(data).hexdigest().upper()


def check_bytes(data, sha, size=None):
    require(digest(data) == sha and (size is None or len(data) == size), "ASSET_BYTES_DIFFER")
    return data


def load_frozen_inputs(raw, expected_sha):
    global ZIP_SHA, ZIP_BYTES, NEW_SHA, FILES, FROZEN_INPUTS_SHA
    require(isinstance(expected_sha, str) and re.fullmatch(r"[0-9A-F]{64}", expected_sha) and expected_sha != "0" * 64, "MAIN_FROZEN_INPUTS_REQUIRED")
    check_bytes(raw, expected_sha)
    values = json.loads(raw)
    require(set(values) == {"schema", "repository", "version", "public_key_sha256", "package_sha256", "package_bytes", "manifest_sha256", "files"}, "FROZEN_INPUTS_SCHEMA")
    require(values["schema"] == 1 and values["repository"] == REPO and values["version"] == "0.1.19.0" and values["public_key_sha256"] == PUBLIC_KEY_SHA, "FROZEN_INPUTS_IDENTITY")
    require(all(isinstance(values[k], str) and re.fullmatch(r"[0-9A-F]{64}", values[k]) and values[k] != "0" * 64 for k in ("package_sha256", "manifest_sha256")), "FROZEN_INPUTS_HASH")
    require(type(values["package_bytes"]) is int and 0 < values["package_bytes"] <= 32 * 1024 * 1024, "FROZEN_INPUTS_SIZE")
    files = values["files"]
    require(isinstance(files, dict) and set(files) == FILE_NAMES, "FROZEN_INPUTS_FILES")
    for entry in files.values():
        require(isinstance(entry, dict) and set(entry) == {"bytes", "sha256"}, "FROZEN_FILE_SCHEMA")
        require(type(entry["bytes"]) is int and 0 < entry["bytes"] <= 32 * 1024 * 1024, "FROZEN_FILE_SIZE")
        require(isinstance(entry["sha256"], str) and re.fullmatch(r"[0-9A-F]{64}", entry["sha256"]) and entry["sha256"] != "0" * 64, "FROZEN_FILE_HASH")
    ZIP_SHA, ZIP_BYTES, NEW_SHA = values["package_sha256"], values["package_bytes"], values["manifest_sha256"]
    FILES = {name: (entry["bytes"], entry["sha256"]) for name, entry in files.items()}
    FROZEN_INPUTS_SHA = expected_sha


def validate_package(manifest, package):
    require(FILES is not None and FROZEN_INPUTS_SHA is not None, "MAIN_FROZEN_INPUTS_REQUIRED")
    check_bytes(manifest, NEW_SHA)
    check_bytes(package, ZIP_SHA, ZIP_BYTES)
    signed = ET.fromstring(manifest)
    require(signed.tag == "signedDashboard" and len(list(signed)) == 2 and bool(signed.findtext("signature")), "MANIFEST_SCHEMA")
    payload = ET.fromstring(base64.b64decode(signed.findtext("payload"), validate=True))
    require(payload.tag == "dashboard" and payload.get("format") == "1" and payload.get("component") == "dashboard" and payload.get("version") == "0.1.19.0", "MANIFEST_IDENTITY")
    require(payload.get("url") == f"https://github.com/{REPO}/releases/download/{TAG}/dashboard.exe", "MANIFEST_URL")
    require(payload.get("sha256") == ZIP_SHA and int(payload.get("bytes")) == ZIP_BYTES, "MANIFEST_PACKAGE")
    require(FILES == {"dashboard.exe": (ZIP_BYTES, ZIP_SHA)}, "PUBLIC_EXECUTABLE_IDENTITY")


def validate_phase(phase):
    require(set(phase) == {"schema", "phase", "repository", "version", "parent_commit", "frozen_inputs_sha256", "main_verification"}, "PHASE_SCHEMA")
    require(phase["schema"] == 1 and phase["repository"] == REPO and phase["version"] == "0.1.19.0", "PHASE_IDENTITY")
    require(phase["phase"] in ("immutable", "promote"), "PHASE_VALUE")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", phase["parent_commit"])) and phase["parent_commit"] != "0" * 40, "PHASE_PARENT")
    require(FROZEN_INPUTS_SHA is not None and phase["frozen_inputs_sha256"] == FROZEN_INPUTS_SHA, "PHASE_FROZEN_INPUTS_PIN")
    proof = phase["main_verification"]
    if phase["phase"] == "immutable":
        require(proof is None, "IMMUTABLE_PHASE_PROOF")
    else:
        fields = {"receipt_sha256", "rsa_verified", "public_resource_inventory_verified", "package_sha256", "manifest_sha256", "release_id", "package_asset_id", "manifest_asset_id", "public_key_sha256", "frozen_inputs_sha256"}
        require(isinstance(proof, dict) and set(proof) == fields, "PROMOTION_PROOF_SCHEMA")
        require(proof["rsa_verified"] is True and proof["public_resource_inventory_verified"] is True, "MAIN_INDEPENDENT_VERIFICATION_REQUIRED")
        require(isinstance(proof["receipt_sha256"], str) and bool(re.fullmatch(r"[0-9A-F]{64}", proof["receipt_sha256"])) and proof["receipt_sha256"] != "0" * 64, "MAIN_RECEIPT_REQUIRED")
        require(proof["public_key_sha256"] == PUBLIC_KEY_SHA and proof["frozen_inputs_sha256"] == FROZEN_INPUTS_SHA, "MAIN_RSA_ANCHOR_AND_INPUTS")
        require(proof["package_sha256"] == ZIP_SHA and proof["manifest_sha256"] == NEW_SHA, "MAIN_HASH_PROOF")
        require(all(type(proof[key]) is int and proof[key] > 0 for key in ("release_id", "package_asset_id", "manifest_asset_id")), "MAIN_ASSET_PROOF")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward an Authorization header to a download CDN.


class Client:
    def __init__(self, token, commit):
        self.token, self.commit = token, commit
        self.started = time.monotonic()
        self.deadline = self.started + 480
        self.auth_opener = urllib.request.build_opener(NoRedirect)

    def bounded(self):
        require(time.monotonic() < self.deadline, "TOTAL_DEADLINE")

    def request(self, method, path, data=None, allow404=False, binary=False, upload=False):
        self.bounded()
        base = "https://uploads.github.com" if upload else "https://api.github.com"
        headers = {"Authorization": "Bearer " + self.token, "User-Agent": "NoranJip-dashboard19-publisher", "X-GitHub-Api-Version": "2022-11-28", "Accept": "application/octet-stream" if binary else "application/vnd.github+json"}
        if data is not None:
            headers["Content-Type"] = "application/octet-stream" if upload else "application/json"
            body = data if upload else json.dumps(data).encode()
        else:
            body = None
        request = urllib.request.Request(base + f"/repos/{REPO}" + path, data=body, headers=headers, method=method)
        try:
            with self.auth_opener.open(request, timeout=30) as response:
                result = response.read((ZIP_BYTES + 1) if binary else (2 * 1024 * 1024 + 1))
                require(len(result) <= (ZIP_BYTES if binary else 2 * 1024 * 1024), "API_RESPONSE_BOUND")
        except urllib.error.HTTPError as error:
            if error.code == 404 and allow404:
                return None
            if binary and error.code in (301, 302, 303, 307, 308):
                return self.public_bytes(error.headers.get("Location", ""), ZIP_BYTES)
            raise Refused("GITHUB_HTTP_" + str(error.code)) from None
        except (urllib.error.URLError, TimeoutError):
            raise Refused("GITHUB_REQUEST_FAILED") from None
        return result if binary else (json.loads(result) if result else None)

    def public_bytes(self, url, maximum):
        self.bounded()
        require(urllib.parse.urlsplit(url).scheme == "https", "HTTPS_REQUIRED")
        try:
            # This request has NO Authorization header, including redirected CDN requests.
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "NoranJip-dashboard19-publisher"}), timeout=30) as response:
                require(urllib.parse.urlsplit(response.url).scheme == "https", "HTTPS_REQUIRED")
                data = response.read(maximum + 1)
        except (urllib.error.URLError, TimeoutError):
            raise Refused("PUBLIC_DOWNLOAD_FAILED") from None
        require(len(data) <= maximum, "DOWNLOAD_BOUND")
        return data

    def source(self, name, maximum):
        require(name in ("phase.json", "frozen-inputs.json", FIXED_NAME, ZIP_NAME), "SOURCE_ALLOWLIST")
        return self.public_bytes(f"https://raw.githubusercontent.com/{REPO}/{self.commit}/{ROOT}{name}", maximum)

    def current_head(self):
        value = self.request("GET", "/git/ref/heads/main")
        require(value["object"]["sha"] == self.commit, "MAIN_HEAD_CHANGED")

    def write(self, method, path, data, upload=False):
        self.current_head()
        return self.request(method, path, data, upload=upload)

    def begin_recovery(self):
        # Reserve at most 90 seconds within the job's ten-minute hard bound.
        self.deadline = min(self.started + 570, time.monotonic() + 90)

    def rollback_old(self):
        # Called only after a fresh exact gap/identity/preservation check below.
        # A changed main head blocks forward writes but must not block restoring
        # the old fixed feed that this transaction just temporarily renamed.
        return self.request("PATCH", f"/releases/assets/{OLD_ID}", {"name": FIXED_NAME})

    def release(self, tag, optional=False):
        return self.request("GET", "/releases/tags/" + urllib.parse.quote(tag, safe=""), allow404=optional)

    def assets(self, release_id):
        result = []
        for page in range(1, 5):
            items = self.request("GET", f"/releases/{release_id}/assets?per_page=100&page={page}")
            result.extend(items)
            if len(items) < 100:
                require(len({x["id"] for x in result}) == len(result) and len({x["name"] for x in result}) == len(result), "DUPLICATE_ASSET")
                return {x["name"]: x for x in result}
        raise Refused("ASSET_PAGINATION_BOUND")

    def bytes(self, asset, sha, size=None):
        data = self.request("GET", f"/releases/assets/{asset['id']}", binary=True)
        require(len(data) == asset["size"], "ASSET_METADATA_SIZE")
        return check_bytes(data, sha, size)

    def latest(self):
        value = self.request("GET", "/releases/latest")
        require(value["id"] == LATEST_ID and value["tag_name"] == LATEST_TAG and not value["draft"] and not value["prerelease"], "LATEST_CHANGED")

    def stable(self):
        release = self.release(STABLE_TAG)
        require(release["id"] == STABLE_ID and not release["draft"] and not release["prerelease"], "STABLE_IDENTITY")
        return self.assets(STABLE_ID)


def metadata(asset):
    return {key: asset.get(key) for key in ("id", "name", "size", "digest", "content_type", "label")}


def preserved(before, after, rename_old=False, promoted_id=None, restore_old=False):
    by_id = {x["id"]: x for x in after.values()}
    for asset in before.values():
        expected = metadata(asset)
        if rename_old and asset["id"] == OLD_ID:
            expected["name"] = OLD_NAME
        if restore_old and asset["id"] == OLD_ID:
            expected["name"] = FIXED_NAME
        if promoted_id == asset["id"]:
            expected["name"] = FIXED_NAME
        require(asset["id"] in by_id and metadata(by_id[asset["id"]]) == expected, "PREEXISTING_ASSET_CHANGED")


def stable_state(client, assets):
    fixed, old, stage = (assets.get(x) for x in (FIXED_NAME, OLD_NAME, STAGE_NAME))
    if old is not None:
        require(old["id"] == OLD_ID, "OLD40_BACKUP_IDENTITY")
        client.bytes(old, OLD_SHA, 977)
    if stage is not None:
        client.bytes(stage, NEW_SHA)
    if fixed is not None and fixed["id"] == OLD_ID:
        require(old is None, "OLD40_DUPLICATE")
        client.bytes(fixed, OLD_SHA, 977)
        return "old"
    if fixed is None:
        require(old is not None and stage is not None, "STABLE_GAP_UNRECOGNIZED")
        return "gap"
    require(old is not None and stage is None, "STABLE_CONFLICT")
    client.bytes(fixed, NEW_SHA)
    return "new"


def immutable(client, manifest, package):
    release = client.release(TAG, optional=True)
    if release is None:
        require(client.request("GET", "/git/ref/tags/" + TAG, allow404=True) is None, "VERSION_TAG_ALREADY_EXISTS")
        release = client.write("POST", "/releases", {"tag_name": TAG, "target_commitish": client.commit, "name": TAG, "draft": True, "prerelease": False, "make_latest": "false", "body": "NoranJip dashboard 0.1.19: prefills both server Windows usernames, preserves client display settings, and lets Windows manage optional saved credentials. Retains the validated VPN and shared loading flow. External client login and reconnect retests remain required. No passwords or VPN private keys are included."})
    require(release["tag_name"] == TAG and not release["prerelease"], "IMMUTABLE_IDENTITY")
    assets = client.assets(release["id"])
    wanted = {ZIP_NAME: (package, ZIP_SHA), FIXED_NAME: (manifest, NEW_SHA)}
    require(set(assets).issubset(wanted), "IMMUTABLE_UNEXPECTED_ASSET")
    # Check every existing object before uploading any missing object. Never overwrite.
    for name, asset in assets.items():
        client.bytes(asset, wanted[name][1], len(wanted[name][0]))
    for name, (data, sha) in wanted.items():
        if name not in assets:
            asset = client.write("POST", f"/releases/{release['id']}/assets?name={urllib.parse.quote(name, safe='')}", data, upload=True)
            client.bytes(asset, sha, len(data))
    assets = client.assets(release["id"])
    require(set(assets) == set(wanted), "IMMUTABLE_ASSET_SET")
    for name, (data, sha) in wanted.items():
        client.bytes(assets[name], sha, len(data))
    if release["draft"]:
        release = client.write("PATCH", f"/releases/{release['id']}", {"draft": False, "make_latest": "false"})
    require(not release["draft"] and not release["prerelease"], "IMMUTABLE_NOT_PUBLIC")
    for name, (data, sha) in wanted.items():
        public = f"https://github.com/{REPO}/releases/download/{TAG}/{urllib.parse.quote(name, safe='')}"
        check_bytes(client.public_bytes(public, len(data)), sha, len(data))
    return release, assets


def promote(client, manifest, proof):
    release = client.release(TAG)
    require(not release["draft"] and not release["prerelease"] and release["id"] == proof["release_id"], "VERIFIED_IMMUTABLE_IDENTITY")
    immutable_assets = client.assets(release["id"])
    require(set(immutable_assets) == {ZIP_NAME, FIXED_NAME}, "VERIFIED_IMMUTABLE_ASSETS")
    for name, key, sha in ((ZIP_NAME, "package_asset_id", ZIP_SHA), (FIXED_NAME, "manifest_asset_id", NEW_SHA)):
        require(immutable_assets[name]["id"] == proof[key], "VERIFIED_IMMUTABLE_ASSET_ID")
        client.bytes(immutable_assets[name], sha)
    before = client.stable()
    state = stable_state(client, before)
    stage = before.get(STAGE_NAME)
    if state == "new":
        return before[FIXED_NAME], "already_promoted"
    if stage is None:
        stage = client.write("POST", f"/releases/{STABLE_ID}/assets?name={STAGE_NAME}", manifest, upload=True)
        client.bytes(stage, NEW_SHA, len(manifest))
    current = client.stable()
    preserved(before, current)
    require(stable_state(client, current) == state and current[STAGE_NAME]["id"] == stage["id"], "PROMOTION_PRESTATE_CHANGED")
    client.latest()
    # Asset renames are sequential. A failed/unknown response is reconciled; no delete.
    try:
        if state == "old":
            client.write("PATCH", f"/releases/assets/{OLD_ID}", {"name": OLD_NAME})
        client.write("PATCH", f"/releases/assets/{stage['id']}", {"name": FIXED_NAME})
    except Exception as failure:
        client.begin_recovery()
        observed = client.stable()
        observed_state = stable_state(client, observed)
        if observed_state == "old":
            preserved(before, observed)
            raise Refused("PROMOTION_STOPPED_OLD_FEED_INTACT") from None
        if observed_state == "new":
            require(observed[FIXED_NAME]["id"] == stage["id"], "PROMOTION_RECOVERY_REVIEW_REQUIRED")
        else:
            require(observed_state == "gap", "PROMOTION_RECOVERY_REVIEW_REQUIRED")
            require(observed[STAGE_NAME]["id"] == stage["id"], "PROMOTION_RECOVERY_REVIEW_REQUIRED")
            preserved(before, observed, rename_old=True)
            client.latest()
            # Only this exact old ID -> fixed-name restoration bypasses HEAD.
            # No version upload or forward promotion bypasses the HEAD guard.
            try:
                client.rollback_old()
            except Exception:
                pass  # Re-read before deciding whether this response was lost.
            restored = client.stable()
            require(stable_state(client, restored) == "old", "PROMOTION_RECOVERY_REVIEW_REQUIRED")
            preserved(before, restored, restore_old=True)
            code = "PROMOTION_STOPPED_OLD_FEED_RESTORED"
            if str(failure) == "MAIN_HEAD_CHANGED":
                code += "_AFTER_HEAD_CHANGE"
            raise Refused(code) from None
    after = client.stable()
    require(stable_state(client, after) == "new" and after[FIXED_NAME]["id"] == stage["id"], "PROMOTION_POSTSTATE")
    preserved(before, after, rename_old=True, promoted_id=stage["id"])
    check_bytes(client.public_bytes(f"https://github.com/{REPO}/releases/download/{STABLE_TAG}/{FIXED_NAME}", len(manifest)), NEW_SHA, len(manifest))
    return after[FIXED_NAME], "promoted"


def main():
    require(os.environ.get("GITHUB_REPOSITORY") == REPO and os.environ.get("GITHUB_REF") == "refs/heads/main" and os.environ.get("GITHUB_EVENT_NAME") == "push", "RUNNER_CONTEXT")
    commit = os.environ.get("GITHUB_SHA", "")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", commit)), "COMMIT_PIN")
    token = os.environ.get("GH_TOKEN", "")
    require(bool(token), "ACTIONS_TOKEN_REQUIRED")
    client = Client(token, commit)
    phase = json.loads(client.source("phase.json", 8192))
    load_frozen_inputs(client.source("frozen-inputs.json", 16384), phase.get("frozen_inputs_sha256"))
    validate_phase(phase)
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as stream:
        event = json.load(stream)
    require(event["before"] == phase["parent_commit"] and event["after"] == commit, "PHASE_EVENT_PIN")
    client.current_head()
    client.latest()
    manifest = client.source(FIXED_NAME, 16384)
    package = client.source(ZIP_NAME, ZIP_BYTES)
    validate_package(manifest, package)
    if phase["phase"] == "immutable":
        before = client.stable()
        require(stable_state(client, before) == "old", "IMMUTABLE_EXPECTS_OLD_STABLE")
        release, assets = immutable(client, manifest, package)
        after = client.stable()
        require(stable_state(client, after) == "old", "STABLE_CHANGED_DURING_IMMUTABLE")
        preserved(before, after)
        result = {"phase": "immutable", "result": "PUBLISHED_EXACT_BYTES", "release_id": release["id"], "package_asset_id": assets[ZIP_NAME]["id"], "manifest_asset_id": assets[FIXED_NAME]["id"]}
    else:
        asset, status = promote(client, manifest, phase["main_verification"])
        result = {"phase": "promote", "result": status, "fixed_asset_id": asset["id"], "preserved_old40_asset_id": OLD_ID, "main_verification_receipt_sha256": phase["main_verification"]["receipt_sha256"]}
    client.latest()
    client.current_head()
    result.update(commit=commit, manifest_sha256=NEW_SHA, package_sha256=ZIP_SHA, package_bytes=ZIP_BYTES, exact_files=1, latest_release_id=LATEST_ID, public_key_sha256=PUBLIC_KEY_SHA, frozen_inputs_sha256=FROZEN_INPUTS_SHA, private_signer_used=False, signal_changed=False)
    print(json.dumps(result, sort_keys=True))
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
        stream.write("```json\n" + json.dumps(result, indent=2, sort_keys=True) + "\n```\n")


if __name__ == "__main__":
    try:
        main()
    except Refused as error:
        print("PUBLICATION_REFUSED " + str(error), file=sys.stderr)
        sys.exit(2)
    except Exception:
        # Never dump raw API responses, URLs with signed query strings, or token data.
        print("PUBLICATION_REFUSED UNCLASSIFIED_FAILURE", file=sys.stderr)
        sys.exit(2)

