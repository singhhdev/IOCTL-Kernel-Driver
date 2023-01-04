#include <ntddk.h>

#include <minwindef.h>

#include "api.h"
#include "structs.h"
#include <minwindef.h>
#include "functions.h"
#include "memory.h"

NTKERNELAPI
NTSTATUS
IoCreateDriver(
	IN PUNICODE_STRING DriverName, OPTIONAL
	IN PDRIVER_INITIALIZE InitializationFunction
);
// IOCTLS:
#define IOCTL_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN,  0x001, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN,  0x002, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_GUARDEDREGION CTL_CODE(FILE_DEVICE_UNKNOWN,  0x003, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_BASE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN,  0x004, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

//DRIVER NAME:

#define drv_device L"\\Device\\VANISHED"
#define drv_dos_device L"\\DosDevices\\VANISHED"
#define drv  L"\\Driver\\VANISHED"


// predeclared functions:
NTSTATUS MajorFunctionClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS MajorFunctionCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject);
NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp);
NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp);

// first declare the device name and driver name for var usage:
PDEVICE_OBJECT pDeviceObject;
UNICODE_STRING deviceName;  
UNICODE_STRING dosName; 

// handle all of the codes here:
NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

	ULONG BytesIO = 0;
	NTSTATUS finalStatus = STATUS_UNSUCCESSFUL;
	PIO_STACK_LOCATION currentStack = IoGetCurrentIrpStackLocation(Irp);
	ULONG controlCode = currentStack->Parameters.DeviceIoControl.IoControlCode;

	if (controlCode == IOCTL_READ_REQUEST) {
		size_t memsize = 0;
		readRequest ReadInput = (readRequest)Irp->AssociatedIrp.SystemBuffer;
		if (ReadInput->SourceProcessID == 0 || ReadInput->SourceAddress == 0) return STATUS_UNSUCCESSFUL;
		ReadProcessMemory(ReadInput->SourceProcessID, (void*)ReadInput->SourceAddress, (void*)ReadInput->ReturnAddress, ReadInput->Size, &memsize);
		finalStatus = STATUS_SUCCESS;
		BytesIO = sizeof(read);
	}
	else if (controlCode == IOCTL_WRITE_REQUEST) {
		size_t memsize = 0;
		writeRequest ReadInput = (writeRequest)Irp->AssociatedIrp.SystemBuffer;
		if (ReadInput->SourceProcessID == 0 || ReadInput->SourceAddress == 0) return STATUS_UNSUCCESSFUL;
		WriteProcessMemory(ReadInput->SourceProcessID, (void*)ReadInput->SourceAddress, (void*)ReadInput->ReturnAddress, ReadInput->Size, &memsize);
		finalStatus = STATUS_SUCCESS;
		BytesIO = sizeof(write);
	}
	else if (controlCode == IOCTL_BASE_REQUEST) {

		PEPROCESS process = NULL;
		baseRequest ReadInput = (baseRequest)Irp->AssociatedIrp.SystemBuffer;
		if (ReadInput->TargetProcessID == 0) {
			return STATUS_UNSUCCESSFUL;
		}
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)ReadInput->TargetProcessID, &process);
		if (status == STATUS_UNSUCCESSFUL) {
			return STATUS_UNSUCCESSFUL;
		}
		uint64_t baseaddy = PsGetProcessSectionBaseAddress(process);
		ObDereferenceObject(process);
		if (!baseaddy) {
			ObDereferenceObject(process);
			return STATUS_UNSUCCESSFUL;
		}
		ReadInput->ReturnAddress = baseaddy;
		finalStatus = STATUS_SUCCESS;
		BytesIO = sizeof(baseAddress);
	}
	else if (controlCode == IOCTL_GUARDEDREGION) {

		guardedRequest ReadInput = (guardedRequest)Irp->AssociatedIrp.SystemBuffer;

		uint64_t GuardedRegion = find_guarded_region();
		if (!GuardedRegion) return STATUS_UNSUCCESSFUL;

		ReadInput->GuardedRegion = GuardedRegion;

		finalStatus = STATUS_SUCCESS;
		BytesIO = sizeof(guardedRegion);

	}
	else {
		finalStatus = STATUS_INVALID_PARAMETER;
		BytesIO = 0;
	}

	Irp->IoStatus.Status = finalStatus;
	Irp->IoStatus.Information = BytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return finalStatus;
}

// MAKE DRIVER HERE FOR KDMAPPER:
NTSTATUS init(PDRIVER_OBJECT driver, PUNICODE_STRING path) {
	// make the device ins:
	RtlInitUnicodeString(&deviceName, drv_device);
	RtlInitUnicodeString(&dosName, drv_dos_device);

	// create device
	//  IoCreateDevice(driver, 0, &deviceName, 0x22u, 0, 1u, &pDeviceObject);
	IoCreateDevice(driver, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	// create symbolic link:
	IoCreateSymbolicLink(&dosName, &deviceName);

	// assign all major functions to driver:
	driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	driver->MajorFunction[IRP_MJ_CREATE] = CreateCall;
	driver->MajorFunction[IRP_MJ_CLOSE] = CloseCall;
	driver->DriverUnload = UnloadDriver;

	//pDeviceObject->Flags |= DO_DIRECT_IO;
	//pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	return STATUS_SUCCESS;
}

NTSTATUS RealDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegsitryPath) {
	// kdmapper does not allow the driver to be created in driver entry.
	NTSTATUS status;
	UNICODE_STRING drv_name;

	RtlInitUnicodeString(&drv_name, drv);
	// make driver here:
	return IoCreateDriver(&drv_name, &init);

}
NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject) {

	IoDeleteSymbolicLink(&dosName);
	IoDeleteDevice(pDriverObject->DeviceObject);
}
NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
