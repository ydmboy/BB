# Sample Windows Kernel Driver

This project contains a minimal Windows kernel-mode driver that logs messages when it is loaded and unloaded.

## Visual Studio 2019 Project

The driver is provided as a Visual Studio 2019 solution.
Open `SampleDriver.sln` in Visual Studio with the Windows Driver Kit (WDK) installed.

1. Select the desired configuration (Debug or Release) and platform (x64).
2. Build the `SampleDriver` project to produce `HelloDriver.sys`.

## Running

After building, load the driver using the `sc` utility from an elevated command prompt:

```cmd
sc create HelloDriver type= kernel binPath= C:\\Path\\To\\HelloDriver.sys
sc start HelloDriver
```

Use Sysinternals DebugView or WinDbg to confirm the driver loaded by observing the debug output:

```text
[SampleDriver] Loaded.
```

Unload and remove the driver with:

```cmd
sc stop HelloDriver
sc delete HelloDriver
```

Likewise, verify the driver unloads by checking the debug output for:

```text
[SampleDriver] Unloading.
```

