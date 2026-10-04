#!/usr/bin/env python3
"""面向 Unity IL2CPP Android APK 的通用 BepInEx 装配器。

将独立的 BepInEx/CoreCLR/bootstrap 运行时注入 APK：
- 读取 APK 内明文的 global-metadata.dat（如有加密请自行解密）；
- 在 UnityPlayer.smali 的 NativeLoader 成功分支插入 bootstrap 调用；
- 组装 assets/mod 载荷并合并、zipalign，输出未签名 APK。
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path


ABI = "arm64-v8a"
METADATA = "assets/bin/Data/Managed/Metadata/global-metadata.dat"
UNITY_PLAYER = "com/unity3d/player/UnityPlayer.smali"
BOOTSTRAP_CLASS = "Lcom/metamiku/modbootstrap/Bootstrap;"
PATCH_CALL = "    invoke-static {}, Lcom/metamiku/modbootstrap/Bootstrap;->load()V\n"
SIGNATURE_RE = re.compile(r"^META-INF/(?:MANIFEST\.MF|[^/]+\.(?:SF|RSA|DSA))$", re.I)
NATIVE_LOAD_BRANCH_RE = re.compile(
    r"(?P<prefix>invoke-static\s+\{[^}]+\},\s+"
    r"Lcom/unity3d/player/NativeLoader;->load\([^)]*\)Z\s*\n"
    r"\s*move-result\s+(?P<result>[vp]\d+)\s*\n"
    r"\s*if-eqz\s+(?P=result),\s*:[^\s]+\s*\n)"
)
REQUIRED_BEPINEX_CORE = {
    "0Harmony.dll",
    "BepInEx.Core.dll",
    "BepInEx.Preloader.Core.dll",
    "BepInEx.Unity.IL2CPP.dll",
    "Il2CppInterop.HarmonySupport.dll",
    "Il2CppInterop.Runtime.dll",
    "Microsoft.Extensions.DependencyInjection.Abstractions.dll",
    "Microsoft.Extensions.DependencyInjection.dll",
    "Microsoft.Extensions.Logging.Abstractions.dll",
    "Microsoft.Extensions.Logging.dll",
    "Microsoft.Extensions.Options.dll",
    "Microsoft.Extensions.Primitives.dll",
    "MonoMod.RuntimeDetour.dll",
}
REQUIRED_RUNTIME = {
    "System.Private.CoreLib.dll",
    "libSystem.Globalization.Native.so",
    "libSystem.IO.Compression.Native.so",
    "libSystem.Native.so",
    "libSystem.Security.Cryptography.Native.Android.dex",
    "libSystem.Security.Cryptography.Native.Android.so",
    "libclrjit.so",
    "libcoreclr.so",
}


class PatchError(RuntimeError):
    pass


@dataclass(frozen=True)
class Payload:
    root: Path
    native: Path
    dex_files: tuple[Path, ...]


def fail(message: str) -> None:
    raise PatchError(message)


def command(value: str | Path) -> list[str]:
    value = str(value)
    if value.lower().endswith(".jar"):
        return ["java", "-Xmx4g", "-jar", value]
    return [value]


def display_command(args: list[str]) -> str:
    return " ".join(map(str, args))


def run(args: list[str], *, cwd: Path | None = None, check: bool = True) -> str:
    print("+", display_command(args))
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True)
    output = (result.stdout or "") + (result.stderr or "")
    if check and result.returncode:
        tail = "\n".join(output.splitlines()[-30:])
        fail(f"command failed ({result.returncode}): {display_command(args)}\n{tail}")
    return output


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sdk_tool(name: str, explicit: str | None = None) -> str:
    if explicit:
        return explicit
    candidates = [
        name,
        str(Path(os.environ.get("ANDROID_SDK_ROOT", "")) / "build-tools/37.0.0" / name),
    ]
    for candidate in candidates:
        if candidate and (Path(candidate).is_file() or shutil.which(candidate)):
            return candidate
    fail(f"Android SDK tool not found: {name}")


def is_arm64_elf(path: Path) -> bool:
    with path.open("rb") as source:
        header = source.read(20)
    return header[:4] == b"\x7fELF" and header[4:6] == b"\x02\x01" and header[18:20] == b"\xb7\x00"


def load_metadata(apk: Path, metadata_file: Path | None = None) -> bytes:
    if metadata_file:
        if not metadata_file.is_file():
            fail(f"metadata file not found: {metadata_file}")
        metadata = metadata_file.read_bytes()
    else:
        with zipfile.ZipFile(apk) as archive:
            if METADATA not in archive.namelist():
                fail(f"APK has no {METADATA}")
            metadata = archive.read(METADATA)
    if len(metadata) < 8 or metadata[:4] != b"\xaf\x1b\xb1\xfa":
        fail("global-metadata.dat is not plain IL2CPP metadata; decrypt it first or pass a decrypted --metadata-file")
    return metadata


def patch_smali(decoded: Path) -> Path:
    matches = list(decoded.glob("smali*/" + UNITY_PLAYER))
    if len(matches) != 1:
        fail(f"expected one UnityPlayer.smali, found {len(matches)}")
    path = matches[0]
    text = path.read_text(encoding="utf-8")
    if BOOTSTRAP_CLASS in text:
        fail("APK is already patched")
    if len(NATIVE_LOAD_BRANCH_RE.findall(text)) != 1:
        fail("could not uniquely locate the NativeLoader success branch")
    path.write_text(
        NATIVE_LOAD_BRANCH_RE.sub(r"\g<prefix>\n" + PATCH_CALL, text, count=1),
        encoding="utf-8",
    )
    return path


def write_bootstrap_smali(unity_smali: Path) -> Path:
    dex_root = next((parent for parent in unity_smali.parents if parent.name.startswith("smali")), None)
    if dex_root is None:
        fail("could not locate the Unity smali dex directory")
    target = dex_root / "com/metamiku/modbootstrap/Bootstrap.smali"
    if target.exists():
        fail("APK already contains the bootstrap class")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        ".class public final Lcom/metamiku/modbootstrap/Bootstrap;\n"
        ".super Ljava/lang/Object;\n\n"
        ".field private static loaded:Z\n\n"
        ".method public static synchronized load()V\n"
        "    .locals 1\n"
        "    sget-boolean v0, Lcom/metamiku/modbootstrap/Bootstrap;->loaded:Z\n"
        "    if-nez v0, :done\n"
        "    const-string v0, \"modbootstrap\"\n"
        "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
        "    const/4 v0, 0x1\n"
        "    sput-boolean v0, Lcom/metamiku/modbootstrap/Bootstrap;->loaded:Z\n"
        ":done\n"
        "    return-void\n"
        ".end method\n",
        encoding="utf-8",
    )
    return target


def safe_relative(value: str) -> str:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        fail(f"unsafe relative path: {value}")
    return path.as_posix()


def stage_payload(
    work: Path,
    apk: Path,
    bepinex_dir: Path,
    dotnet_dir: Path,
    bootstrap_dir: Path,
    dobby: Path,
    metadata_bytes: bytes,
    unity_libs: Path | None,
) -> Payload:
    missing_bepinex = sorted(
        name for name in REQUIRED_BEPINEX_CORE if not (bepinex_dir / "core" / name).is_file()
    )
    if missing_bepinex:
        fail("--bepinex-dir/core is missing: " + ", ".join(missing_bepinex))
    if not dotnet_dir.is_dir():
        fail(f"--dotnet-dir is not a directory: {dotnet_dir}")
    missing_runtime = sorted(name for name in REQUIRED_RUNTIME if not (dotnet_dir / name).is_file())
    if missing_runtime:
        fail("--dotnet-dir is missing: " + ", ".join(missing_runtime))
    root = work / "payload"
    if root.exists():
        fail(f"payload work directory already exists: {root}")
    assets = root / "assets/mod"
    native = root / "native/lib" / ABI
    dex = root / "dex"
    assets.mkdir(parents=True)
    native.mkdir(parents=True)
    dex.mkdir(parents=True)
    manifest: list[str] = []
    native_names: dict[str, str] = {}

    def add_tree(source: Path, destination: str, skip_suffixes: set[str] | None = None) -> None:
        destination = safe_relative(destination)
        for path in sorted(source.rglob("*")):
            if not path.is_file():
                continue
            if skip_suffixes and path.suffix.lower() in skip_suffixes:
                continue
            relative = safe_relative(str(path.relative_to(source)))
            target = assets / destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            manifest.append(f"mod/{destination}/{relative}\t{destination}/{relative}")

    add_tree(bepinex_dir, "BepInEx")
    add_tree(dotnet_dir, "dotnet", {".so", ".dex", ".jar"})

    dex_names: set[str] = set()
    for source in sorted(dotnet_dir.rglob("*.dex")):
        if source.name in dex_names:
            fail(f"conflicting runtime DEX named {source.name}")
        if not source.read_bytes().startswith(b"dex\n"):
            fail(f"invalid runtime DEX: {source}")
        dex_names.add(source.name)
        shutil.copy2(source, dex / source.name)
    (assets / "BepInEx").mkdir(parents=True, exist_ok=True)
    (assets / "BepInEx/global-metadata.dat").write_bytes(metadata_bytes)
    manifest.append("mod/BepInEx/global-metadata.dat\tBepInEx/global-metadata.dat")

    if unity_libs:
        if not unity_libs.is_file() or unity_libs.suffix.lower() != ".zip":
            fail("--unity-libs must point to a ZIP file")
        target = assets / "BepInEx/unity-libs" / unity_libs.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(unity_libs, target)
        manifest.append(f"mod/BepInEx/unity-libs/{unity_libs.name}\tBepInEx/unity-libs/{unity_libs.name}")

    write_config(root, unity_libs)
    config_manifest = "mod/BepInEx/config/BepInEx.cfg\tBepInEx/config/BepInEx.cfg"
    if config_manifest not in manifest:
        manifest.append(config_manifest)

    with zipfile.ZipFile(apk) as archive:
        if "assets/bin/Data/globalgamemanagers" not in archive.namelist():
            fail("APK has no globalgamemanagers file")
        game = assets / "game/Data/globalgamemanagers"
        game.parent.mkdir(parents=True, exist_ok=True)
        game.write_bytes(archive.read("assets/bin/Data/globalgamemanagers"))
    manifest.append("mod/game/Data/globalgamemanagers\tgame/Data/globalgamemanagers")

    def add_native(path: Path) -> None:
        if not path.is_file() or path.suffix != ".so":
            fail(f"native library not found: {path}")
        if not is_arm64_elf(path):
            fail(f"native library is not Android arm64 ELF: {path}")
        name = path.name
        digest = sha256(path.read_bytes())
        if name in native_names and native_names[name] != digest:
            fail(f"conflicting native libraries named {name}")
        native_names[name] = digest
        shutil.copy2(path, native / name)

    bootstrap_so = bootstrap_dir / "lib" / ABI / "libmodbootstrap.so"
    add_native(bootstrap_so)
    add_native(dobby)
    for path in sorted(dotnet_dir.rglob("*.so")):
        add_native(path)
    native_list = "\n".join(
        name for name in sorted(native_names) if name != "libmodbootstrap.so"
    ) + "\n"
    (assets / "native-libs.txt").write_text(native_list, encoding="utf-8")
    manifest.extend(["mod/native-libs.txt\tnative-libs.txt", "mod/payload.version\tpayload.version"])

    version_digest = hashlib.sha256()
    for path in sorted(assets.rglob("*")):
        if path.is_file() and path.name not in {"manifest.txt", "payload.version"}:
            version_digest.update(path.relative_to(assets).as_posix().encode())
            version_digest.update(path.read_bytes())
    for path in sorted(native.rglob("*.so")):
        version_digest.update(path.name.encode())
        version_digest.update(path.read_bytes())
    for path in sorted(dex.rglob("*.dex")):
        version_digest.update(path.name.encode())
        version_digest.update(path.read_bytes())
    version = version_digest.hexdigest()
    (assets / "payload.version").write_text(version + "\n", encoding="ascii")
    (assets / "manifest.txt").write_text("\n".join(manifest) + "\n", encoding="utf-8")
    return Payload(root, native, tuple(sorted(dex.rglob("*.dex"))))


def write_config(payload: Path, unity_libs: Path | None) -> None:
    config = payload / "assets/mod/BepInEx/config/BepInEx.cfg"
    config.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "[Logging]",
        "LogLevels = Fatal, Error, Warning, Message, Info, Debug",
        "UnityLogListening = false",
        "",
        "[IL2CPP]",
        "GlobalMetadataPath = {BepInEx}/global-metadata.dat",
        f"UpdateInteropAssemblies = {'true' if unity_libs else 'false'}",
        "ScanMethodRefs = false",
    ]
    if unity_libs:
        lines.append(f"UnityBaseLibrariesSource = {unity_libs.name}")
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")


def is_signature(name: str) -> bool:
    return bool(SIGNATURE_RE.match(name))


def copy_zip_entry(output: zipfile.ZipFile, info: zipfile.ZipInfo, data: bytes) -> None:
    output.writestr(info, data)


def merge_apk(original: Path, rebuilt: Path, output: Path, payload: Payload) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    native_names = {f"lib/{ABI}/{path.name}" for path in payload.native.rglob("*.so")}
    written: set[str] = set()
    with zipfile.ZipFile(output, "w") as destination:
        with zipfile.ZipFile(rebuilt) as source:
            for info in source.infolist():
                name = info.filename
                if is_signature(name) or name.startswith("assets/") or name in native_names:
                    continue
                if name in written:
                    fail(f"rebuilt APK contains duplicate entry: {name}")
                copy_zip_entry(destination, info, source.read(info))
                written.add(name)
        with zipfile.ZipFile(original) as source:
            for info in source.infolist():
                name = info.filename
                if not name.startswith("assets/") or name in written:
                    continue
                copy_zip_entry(destination, info, source.read(info))
                written.add(name)
        for path in sorted((payload.root / "assets").rglob("*")):
            if path.is_file():
                name = path.relative_to(payload.root).as_posix()
                if name in written:
                    fail(f"payload path collides with APK entry: {name}")
                destination.writestr(name, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
                written.add(name)
        for path in sorted(payload.native.rglob("*.so")):
            name = f"lib/{ABI}/{path.name}"
            if name in written:
                fail(f"payload native path collides with APK entry: {name}")
            destination.writestr(name, path.read_bytes(), compress_type=zipfile.ZIP_STORED)
            written.add(name)
        dex_numbers = [
            int(match.group(1) or "1")
            for name in written
            if (match := re.fullmatch(r"classes(\d*)\.dex", name))
        ]
        next_dex = max(dex_numbers, default=0) + 1
        for path in payload.dex_files:
            name = "classes.dex" if next_dex == 1 else f"classes{next_dex}.dex"
            destination.writestr(name, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
            written.add(name)
            next_dex += 1


def apktool_decode(apktool: str, apk: Path, decoded: Path) -> None:
    run(
        command(apktool)
        + ["d", "-f", "-r", "--no-assets", "-j", "8", "-o", str(decoded), str(apk)]
    )


def apktool_build(apktool: str, decoded: Path, rebuilt: Path) -> None:
    run(command(apktool) + ["b", "-f", "-o", str(rebuilt), str(decoded)])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_apk", type=Path)
    parser.add_argument("output_apk", type=Path)
    parser.add_argument("--bepinex-dir", type=Path, required=True)
    parser.add_argument("--dotnet-dir", type=Path, required=True)
    parser.add_argument("--bootstrap-dir", type=Path, required=True)
    parser.add_argument("--dobby", type=Path, required=True)
    parser.add_argument("--unity-libs", type=Path)
    parser.add_argument("--metadata-file", type=Path,
                        help="use this decrypted global-metadata.dat instead of the one inside the APK")
    parser.add_argument("--apktool", default=os.environ.get("APKTOOL", "apktool"))
    parser.add_argument("--zipalign", default=None)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--keep-work", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.input_apk.is_file():
        fail(f"input APK not found: {args.input_apk}")
    if args.input_apk.resolve() == args.output_apk.resolve():
        fail("input APK and output APK must be different files")
    zipalign = sdk_tool("zipalign", args.zipalign)
    args.output_apk.parent.mkdir(parents=True, exist_ok=True)

    work = args.work_dir or Path(tempfile.mkdtemp(prefix="apkpatch-"))
    work.mkdir(parents=True, exist_ok=True)
    try:
        metadata_bytes = load_metadata(args.input_apk, args.metadata_file)
        payload = stage_payload(work, args.input_apk, args.bepinex_dir, args.dotnet_dir,
                                args.bootstrap_dir, args.dobby, metadata_bytes, args.unity_libs)

        decoded = work / "decoded"
        rebuilt = work / "rebuilt-unsigned.apk"
        apktool_decode(args.apktool, args.input_apk, decoded)
        patched_smali = patch_smali(decoded)
        write_bootstrap_smali(patched_smali)
        apktool_build(args.apktool, decoded, rebuilt)

        merged = work / "merged-unsigned.apk"
        merge_apk(args.input_apk, rebuilt, merged, payload)
        aligned = work / "aligned.apk"
        run([zipalign, "-f", "-p", "4", str(merged), str(aligned)])
        shutil.copy2(aligned, args.output_apk)
        print(f"wrote {args.output_apk}")
    finally:
        if not args.keep_work and args.work_dir is None:
            shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PatchError, ValueError, AssertionError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
