# Sample Windows Kernel Driver

This is a minimal Windows kernel-mode driver that prints messages when loaded and unloaded.

## Building

1. Install Visual Studio with the Windows Driver Kit (WDK).
2. Open a "x64 Native Tools Command Prompt" with the WDK environment.
3. Compile using the WDK build tools:
   ```
   cl /EHsc /W4 /nologo /DUNICODE /D_UNICODE /kernel /I"%WDK_DIR%\Include" HelloDriver.c /link /SUBSYSTEM:NATIVE /ENTRY:DriverEntry
   ```

## Running

After building, you can load the driver using the `sc` utility:

```
sc create HelloDriver type= kernel binPath= C:\\Path\\To\\HelloDriver.sys
sc start HelloDriver
```

Unload the driver with:
```
sc stop HelloDriver
sc delete HelloDriver
```
