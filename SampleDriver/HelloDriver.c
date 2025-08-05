#include <ntddk.h>

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[SampleDriver] Unloading.\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrint("[SampleDriver] Loaded.\n");

    DriverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}

