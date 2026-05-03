# unicorn_peEmu

基于 Unicorn 的 Windows PE 仿真实验工程。当前主流程已经精简为一个小型 PE runner：加载 x86/x64 PE、映射镜像和栈、修复导入表到模拟 API stub，并通过 Unicorn 执行入口点。

当前不是完整 Windows 沙箱，只覆盖基础执行链和少量 Kernel32 API。`unit_pe` 用例已覆盖 x86/x64 两个 PE，均可通过仿真输出 `Hello World!`。

## 目录

- `unicorn_build/`：VS 辅助工程，自动用 CMake 编译 Unicorn，并复制依赖库。
- `unicorn_wscript/`：PE 仿真主工程。
- `unit_pe/`：最小测试 PE 工程，生成 x86/x64 两个样本。
- `unicorn-master/`：Unicorn 源码。
- `capstone/`：Capstone 依赖，仓库内已有 `capstone_x86.lib` 和 `capstone_x64.lib`。
- `bin/`：可执行文件输出目录。
- `lib/`：依赖库输出目录。

## 构建

直接打开 `unicorn_wscript.sln`，选择 `Win32` 或 `x64`，再选择 `Debug` 或 `Release` 构建即可。

构建 `unicorn_wscript` 时会先构建 `unicorn_build`：

1. 自动检测 VS2019，找不到时回退到 VS2022。
2. 用 CMake 编译 `unicorn-master`，只启用 x86 架构。
3. 复制 Unicorn 和 Capstone 库到 `lib\<Platform>\<Configuration>\`。
4. `unicorn_wscript` 只通过相对路径 `..\lib\<Platform>\<Configuration>` 链接依赖。

命令行示例：

```powershell
msbuild unicorn_wscript.sln /m /p:Configuration=Release /p:Platform=x64
msbuild unicorn_wscript.sln /m /p:Configuration=Release /p:Platform=Win32
```

## wscript 运行流程

当前入口是 `unicorn_wscript/main.cpp`，默认走轻量 runner `SimplePeEmu`：

1. `SimplePeEmu::Load`：读取 PE，解析 DOS/NT/Section 头。
2. `SimplePeEmu::BuildImage`：按 Section 把文件布局展开为内存镜像。
3. `SimplePeEmu::ResolveImports`：遍历导入表，把 IAT 指向模拟 API stub。
4. `SimplePeEmu::OpenEngine`：按 PE 机器类型选择 `UC_MODE_32` 或 `UC_MODE_64`。
5. `SimplePeEmu::MapImageAndStack`：映射镜像、stub 区和栈，初始化 ESP/RSP。
6. `SimplePeEmu::InstallHooks`：挂代码 hook 和非法内存 hook。
7. `SimplePeEmu::Run`：从 OEP 开始执行；命中 stub 后在 `HandleImport` 中模拟 `GetStdHandle`、`WriteFile`、`ExitProcess`。

旧版 `PeEmu` 代码仍保留，后续扩展完整 Windows 环境时可继续沿用这些入口：

- GDT 初始化：`PeEmu.cpp::InitGdtr`
- IDT/异常：目前没有完整 IDT，只有 `IntrCallback` 和 `InvalidCallback` 的基础 hook。
- PEB/TEB/LDR：`PeEmu.cpp::InitTibPeb_PebLdrdata`
- 系统 DLL 加载：`PeEmu.cpp::InitSysDLL`
- DLL 导出/IAT：`PeEmu.cpp::MapInsertIat`、`MyGetProcess`
- 样本 PE 加载：`PeEmu.cpp::SamplePeMapImage`
- 样本 IAT/重定位：`PeEmu.cpp::InitsampleIatRep`、`RepairTheIAT`、`RepairReloCation`
- WinAPI 回调：`PeEmu.cpp::RegisterEmuWinApi`、`emuwindows.cpp`

## 输出

构建后主要产物位于 `bin/`：

- `unicorn_wscript_x64.exe`
- `unicorn_wscript_x86.exe`
- `unit_pe_x64.exe`
- `unit_pe_x86.exe`

依赖库位于：

- `lib\x64\<Debug|Release>\`
- `lib\Win32\<Debug|Release>\`

## 运行测试

```powershell
bin\unicorn_wscript_x64.exe bin\unit_pe_x64.exe
bin\unicorn_wscript_x64.exe bin\unit_pe_x86.exe
bin\unicorn_wscript_x86.exe bin\unit_pe_x64.exe
bin\unicorn_wscript_x86.exe bin\unit_pe_x86.exe
```

预期输出均为：

```text
Hello World!
```

## 当前 API 覆盖

最小 runner 目前模拟：

- `GetStdHandle`
- `WriteFile`
- `ExitProcess`

其它导入会默认返回 `0` 并打印提示。后续如果要跑更复杂 PE，应逐步补 API、TLS、异常、PEB/TEB/LDR、动态加载 DLL 等行为。

## 参考

- Unicorn: https://github.com/unicorn-engine/unicorn
- unicorn_pe: https://github.com/hzqst/unicorn_pe
