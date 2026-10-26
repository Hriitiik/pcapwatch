from ..models import Finding

PE_EXT = (".exe", ".dll", ".scr", ".sys")
SCRIPT_EXT = (".ps1", ".vbs", ".bat", ".hta", ".sh")


def classify(f):
    path = f.url.split("?")[0].lower()
    if f.head.startswith(b"MZ"):
        return "PE executable", not path.endswith(PE_EXT)
    if f.head.startswith(b"\x7fELF"):
        return "ELF executable", False
    if f.head.startswith(b"#!"):
        return "script", False
    if path.endswith(SCRIPT_EXT):
        return "script", False
    return None, False


def detect_downloads(files):
    findings = []
    for f in files:
        file_type, mismatch = classify(f)
        if file_type is None:
            continue

        note = " (disguised extension)" if mismatch else ""
        findings.append(
            Finding(
                rule="suspicious_download",
                attack_id="T1105",
                src=f.client,
                end=f.ts,
                summary=f"{f.client} downloaded {file_type} from {f.url} ({f.size} bytes, sha256 {f.sha256[:16]}...){note}",
                evidence={
                    "url": f.url,
                    "server": f.server,
                    "port": f.port,
                    "sha256": f.sha256,
                    "content_type": f.content_type,
                    "extension_mismatch": mismatch,
                },
            )
        )
