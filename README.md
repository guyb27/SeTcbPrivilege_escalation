# SeTcbPrivilege-Escalation

Exploit **SeTcbPrivilege** to impersonate any local user without password via S4U (`LsaLogonUser` with `MSV1_0_S4U_LOGON`). Read files, list directories, and execute commands as Administrator. PowerShell + inline C# — no compilation needed.

## How it works

When a Windows service account has `SeTcbPrivilege` ("Act as part of the operating system") enabled, it can call `LsaRegisterLogonProcess` and perform an S4U (Service for User) logon via `LsaLogonUser` with `MSV1_0_S4U_LOGON` (type 12). This creates an impersonation token for any local user — **without knowing their password**.

The script:
1. Enables `SeTcbPrivilege` via `RtlAdjustPrivilege`
2. Registers a logon process with `LsaRegisterLogonProcess`
3. Performs an S4U logon with `LsaLogonUser` (MSV1_0 package, type 12)
4. Calls `ImpersonateLoggedOnUser` to assume the target user's identity
5. Reads files, lists directories, or executes commands in that context

## Requirements

- A shell as a user with **SeTcbPrivilege** (check with `whoami /priv`)
- PowerShell with `Add-Type` support (default on Windows Server 2012+)
- No admin rights needed — SeTcbPrivilege is sufficient

## Usage

Transfer `s4u_run.ps1` to the target, then:

```powershell
# Read a file as Administrator
powershell -ep bypass -File s4u_run.ps1 -Action read -Target "C:\Users\Administrator\Desktop\flag.txt"

# List a directory as Administrator
powershell -ep bypass -File s4u_run.ps1 -Action dir -Target "C:\Users\Administrator\Desktop"

# Execute a command as Administrator
powershell -ep bypass -File s4u_run.ps1 -Action exec -Target "whoami /priv"
```

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-Action` | Yes | — | `read`, `dir`, or `exec` |
| `-Target` | Yes | — | File path, directory path, or command |
| `-User` | No | `Administrator` | User to impersonate |
| `-Domain` | No | `SRV01` | Machine/domain name |

### Impersonate a different user

```powershell
powershell -ep bypass -File s4u_run.ps1 -Action read -User "svc_backup" -Domain "DC01" -Target "C:\secrets.txt"
```

## Example output

```
PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                         State
============================= =================================== ========
SeTcbPrivilege                Act as part of the operating system  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled

PS C:\> powershell -ep bypass -File s4u_run.ps1 -Action read -Target "C:\Users\Administrator\Desktop\flag.txt"
4832d0bd7c24d6e62b6a2afc75392645

PS C:\> powershell -ep bypass -File s4u_run.ps1 -Action dir -Target "C:\Users\Administrator\Desktop"
C:\Users\Administrator\Desktop\desktop.ini
C:\Users\Administrator\Desktop\flag.txt
```

## Note on `exec` action

The `exec` action spawns `cmd.exe /c <command>` under the impersonated thread. However, `whoami` may still show the original user because child processes inherit the **process token**, not the thread impersonation token. File operations (`read`, `dir`) work correctly because they run directly in the impersonated thread context.

## Detection

- Event ID **4624** with Logon Type **12** (S4U / NewCredentials) and package `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`
- Process name registered via `LsaRegisterLogonProcess` (default: `JavaSvc`)
- `Add-Type` usage with P/Invoke signatures for `secur32.dll` / `ntdll.dll`

## References

- [Microsoft — LsaLogonUser function](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsalogonuser)
- [Microsoft — MSV1_0_S4U_LOGON structure](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-msv1_0_s4u_logon)
- [Microsoft — SeTcbPrivilege](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/act-as-part-of-the-operating-system)

## License

[MIT](LICENSE)
