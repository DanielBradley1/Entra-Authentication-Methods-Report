# Entra Authentication Methods Report script
A report dashboard to visualise and track the progress of MFA deployment across your organisation. 

## Installing the script
```
Install-Script -Name Invoke-EntraAuthReport
```

## Prerequisites
- PowerShell 7
- Microsoft.Graph.Authentication

## Graph Permissions (delegated)
- Policy.Read.All
- Organization.Read.All
- AuditLog.Read.All
- UserAuthenticationMethod.Read.All
- RoleAssignmentSchedule.Read.Directory
- RoleEligibilitySchedule.Read.Directory

## Example output

![Entra Auth Report example2](https://github.com/user-attachments/assets/d54b6dec-0be0-4f7e-9a9b-0e3952426b13)
