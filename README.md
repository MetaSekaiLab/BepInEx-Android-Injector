# bepinex-android-injector

Unity IL2CPP Android APK 的通用 BepInEx 启发式装配脚本。

## 依赖

以下仓库请自行编译：

- [BepInEx-Android](https://github.com/MetaSekaiLab/BepInEx-Android)：BepInEx core（`--bepinex-dir`）
- [Il2CppInterop-Android](https://github.com/MetaSekaiLab/Il2CppInterop-Android)：arm64 适配的 Il2CppInterop
- [BepInEx-Android-Bootstrap](https://github.com/MetaSekaiLab/BepInEx-Android-Bootstrap)：`libmodbootstrap.so`（`--bootstrap-dir`）

CoreCLR 运行时（`--dotnet-dir`）、`libdobby.so`、apktool、zipalign 另行准备；`--unity-libs` 可选，用于首次生成 interop。APK 内 metadata 加密时，先用外部工具解密，再通过 `--metadata-file` 覆盖。

## 用法

```bash
python3 injector.py input.apk output.apk \
  --bepinex-dir <BepInEx> \
  --dotnet-dir <dotnet> \
  --bootstrap-dir <bootstrap> \
  --dobby <libdobby.so> \
  --apktool <apktool.jar> \
  [--unity-libs <unity-libs.zip>] \
  [--metadata-file <global-metadata.dat>]
```

## 行为

读取明文 metadata（`--metadata-file` 可覆盖 APK 内的版本）→ 校验并组装 `assets/mod` 载荷 → smali 注入 bootstrap 调用 → 重打包合并 → zipalign，输出未签名 APK。

## License

[MIT](LICENSE)
