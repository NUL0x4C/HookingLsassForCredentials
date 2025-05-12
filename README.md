## HookingLsassForCredentials

</br>

## Explanation

The goal of this PoC is to leverage the registry key discovered [here](https://github.com/Maldev-Academy/LsassHijackingViaReg) to load a DLL into Lsass.exe that will allow us to fetch the user's credentials (in any form possible) while effectively bypassing Credential Guard. It is worth mentioning that when Credential Guard is enabled, Lsass.exe hands over credential protection and caching to LsaIso.exe, however, Lsass.exe remains the one responsible for verifying the login user credentials.

</br>

## How It Works

* The initial objective was to retrieve a populated [USER_INTERNAL6_INFORMATION](https://github.com/winsiderss/phnt/blob/master/ntsam.h#L1430) structure to access the [USER_ALL_INFORMATION](https://github.com/winsiderss/phnt/blob/master/ntsam.h#L1340) structure, allowing us to read critical elements like [NtPassword](https://github.com/winsiderss/phnt/blob/master/ntsam.h#L1359C20-L1359C30) and [LmPassword](https://github.com/winsiderss/phnt/blob/master/ntsam.h#L1358) during initial user authentication process. However, this structure is based on the [WhichFields](https://github.com/winsiderss/phnt/blob/master/ntsam.h#L1199) parameter of the targeted API.

* To capture a `USER_INTERNAL6_INFORMATION` structure, we hooked [samsrv!SamIGetUserLogonInformation2](https://github.com/NUL0x4C/HookingLsassForCredentials/blob/main/DumpHashes/DllMain.c#L855). However this function and its caller (named [lsasrv!LsapSamExtGetUserLogonInformation2](https://github.com/NUL0x4C/HookingLsassForCredentials/blob/main/DumpHashes/DllMain.c#L816)) override their `WhichFields` parameter and forcibly setting it to `0x1B`. This value is explained [here](https://github.com/NUL0x4C/HookingLsassForCredentials/blob/main/DumpHashes/DllMain.c#L1040). Therefore, we thought of manually altering this value to be equal to [USER_ALL_READ_TRUSTED_MASK2](https://github.com/NUL0x4C/HookingLsassForCredentials/blob/main/DumpHashes/DllMain.c#L1049), hoping to read the aforementioned elements. Upon doing this, `SamIGetUserLogonInformation2` returned `STATUS_INVALID_INFO_CLASS` as explained [here](https://github.com/NUL0x4C/HookingLsassForCredentials/blob/main/DumpHashes/DllMain.c#L1293).   

* As an alternative, we placed a hook at the start of the `SamIGetUserLogonInformation2` function. In the detour function, we read `UNICODE_STRING` structures relative to the `R8` register. These structures held valuable information like the plaintext password entered by the user at the lock screen, the username, and the workstation. However, this approach proved unstable (we were unable to fetch valuable data each time), rendering the PoC currently as a *work-in-progress* (WIP).

* It is worth mentioning that the current PoC waits for the LogonUI.exe process to start to install the hook/s. LogonUI.exe is the process responsible for displaying the Windows login screen and securely capturing user credentials.

</br>


## Demo
  

1. Installing the [Dummy DLL](https://github.com/NUL0x4C/HookingLsassForCredentials/tree/main/DumpHashes) and editing the `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\Interfaces\1001` registry key's value to load our DLL that will execute our code and act as a proxy to the `lsasrv.dll` DLL. 

</br>

![PIC1](https://github.com/user-attachments/assets/691b6e80-33f1-4bdd-b195-3cd4bc03eaa1)

</br>
</br>

2. Upon reboot, we captured the login plaintext password with Credential Guard being enabled. The image below is the truncated output of the `cat C:\DummyDebug.log` command. Which is the [DEBUG_FILE](https://github.com/NUL0x4C/HookingLsassForCredentials/blob/main/DumpHashes/Log.h#L4C33-L4C43).

</br>


![PIC2](https://github.com/user-attachments/assets/58944393-5b83-4d45-a3ec-2b969160b28e)


</br>


### Reference:
* [LsassHijackingViaReg](https://github.com/Maldev-Academy/LsassHijackingViaReg)

* [phnt/ntsam.h](https://github.com/winsiderss/phnt/blob/master/ntsam.h)

* [Utilizing Hardware Breakpoints For Hooking (2)](https://maldevacademy.com/new/modules/10)

* [rad98-hooking-engine](https://github.com/vxunderground/VX-API#rad98-hooking-engine)
