<#PSScriptInfo

.VERSION 0.4.0

.GUID bbda77a3-7d1c-415e-9c28-7c934971599c

.AUTHOR Daniel Bradley

.COMPANYNAME ourcloudnetwork.co.uk

.COPYRIGHT

.TAGS
    ourcloudnetwork
    Microsoft Entra
    Microsoft Graph

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES
    Microsoft.Graph.Authentication

.RELEASENOTES
    v0.1 - Initial release
    v0.2 - Fix output path issues
    v0.3 - Added export functionality, examples and increased registration details report size to 20,000.
#>

<#
.DESCRIPTION 
 This script, created by Daniel Bradley at ourcloudnetwork.co.uk, generates a report on the authentication methods registered by users in your Microsoft 365 tenant. The report includes information on the number of users, the percentage of users with strong authentication methods, the percentage of users who are passwordless capable, and more. The script uses the Microsoft Graph API to retrieve the necessary data and the report is built with HTML, CSS and JS.

.PARAMETER outpath
 Specified the output path of the report file.

.PARAMETER limit
 Defines how many userRegistrationDetails records to fetch.

.PARAMETER ignoreguest
 Ignores all the users of type 'guest'.

.PARAMETER openbrowser
 If true, opens the generated report in the browser.

.EXAMPLE
PS> Invoke-EntraAuthReport -outpath "C:\Reports\EntraAuthReport.html"
#>

#Params
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$outpath,

    [Parameter(Mandatory = $false)]
    [int]$limit = 20000,

    [Parameter(Mandatory = $false)]
    [switch]$ignoreguest = $false,

    [Parameter(Mandatory = $false)]
    [switch]$openbrowser = $false
)

# Check Microsoft Graph connection
$state = Get-MgContext

# Define required permissions properly as an array of strings
$requiredPerms = @("Policy.Read.All", "Organization.Read.All", "AuditLog.Read.All", "UserAuthenticationMethod.Read.All", "RoleAssignmentSchedule.Read.Directory", "RoleEligibilitySchedule.Read.Directory")

# Check if we're connected and have all required permissions
$hasAllPerms = $false
if ($state) {
    $missingPerms = @()
    foreach ($perm in $requiredPerms) {
        if ($state.Scopes -notcontains $perm) {
            $missingPerms += $perm
        }
    }
    if ($missingPerms.Count -eq 0) {
        $hasAllPerms = $true
        Write-output "Connected to Microsoft Graph with all required permissions"
    }
    else {
        Write-output "Missing required permissions: $($missingPerms -join ', ')"
        Write-output "Reconnecting with all required permissions..."
    }
}
else {
    Write-output "Not connected to Microsoft Graph. Connecting now..."
}

# Connect if we need to
if (-not $hasAllPerms) {
    try {
        Connect-MgGraph -Scopes $requiredPerms -ErrorAction Stop -NoWelcome
        Write-output "Successfully connected to Microsoft Graph"
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        exit
    }
}

#Check tenant level license plan
$items = @("AAD_PREMIUM_P2", "AAD_PREMIUM", "AAD_BASIC")
$Skus = Invoke-MgGraphRequest -Uri "Beta/subscribedSkus" -OutputType PSObject | Select -Expand Value
foreach ($item in $items) {
    $Search = $skus | ? { $_.ServicePlans.servicePlanName -contains "$item" }
    if ($Search) {
        $licenseplan = $item
        break
    }
    ElseIf ((!$Search) -and ($item -eq "AAD_BASIC")) {
        $licenseplan = $item
        break
    }
}

#Get organisation name
$organisationName = (Invoke-MgGraphRequest -Uri "v1.0/organization" -OutputType PSObject | Select -Expand value).DisplayName

#Return an array of authentication methods including whether they are enabled or not and for which users
Function Get-AuthenticationMethods {
    $policies = Invoke-MgGraphRequest -Uri "beta/policies/authenticationmethodspolicy" -OutputType PSObject | Select -Expand authenticationMethodConfigurations
    $policiesReport = [System.Collections.Generic.List[Object]]::new()
    forEach ($policy in $policies) {
        $obj = [PSCustomObject][ordered]@{
            "Type"        = if ($policy.displayName) { "Custom" }else { "Built-in" }
            "DisplayName" = if ($policy.displayName) { $policy.displayName }else { $policy.id }
            "State"       = $policy.state
            "Aliases"     = ($policy.includeTargets.id -join [environment]::NewLine)
        }
        $policiesReport.Add($obj)
    }
    return $policiesReport
}

Function Get-UserRegistrationDetails {
    #Lists all users and their user mfa registration details including their default method
    $userRegistrations = Invoke-MgGraphRequest -Uri "Beta/reports/authenticationMethods/userRegistrationDetails?`$top=$limit&`$orderby=userPrincipalName" -OutputType PSObject | Select -Expand Value
    
    if ($ignoreguest) {
        $userRegistrations = $userRegistrations | Where-Object { $_.userType -ne "guest" }
    }

    $usersWithMobileMethods = $userRegistrations | where { $_.methodsRegistered -contains "mobilePhone" } | Select userPrincipalName, methodsRegistered
    $userRegistrationsMethods = [System.Collections.Generic.List[Object]]::new()
    Foreach ($user in $usersWithMobileMethods) {
        $Methods = Invoke-MgGraphRequest -uri "/beta/users/$($user.userPrincipalName)/authentication/methods" -OutputType PSObject | WHere { $_."@odata.type" -eq '#microsoft.graph.phoneAuthenticationMethod' }
        if ($Methods.smsSignInState -eq "ready") { $phoneinfo = @("Voice Call", "SMS") }else { $phoneinfo = @("Voice Call") }
        $methodsFromReport = ($userRegistrations | where { $_.userPrincipalName -eq $user.userPrincipalName }).methodsRegistered
        $methodsToReplace = @()
        $methodsToReplace += $methodsFromReport | where { $_ -ne "mobilePhone" }
        foreach ($item in $phoneinfo) { $methodsToReplace += $item }
        ($userRegistrations | where { $_.userPrincipalName -eq $user.userPrincipalName }).methodsRegistered = $methodsToReplace
    }
    
    return $userRegistrations
}

Function Get-PrivilegedUserRegistrationDetails {
    [CmdletBinding()]
    param (
        [Parameter()]
        $userRegistrations
    )
    If ($licenseplan -eq "AAD_PREMIUM_P2") {
        #Get all members (eligible and assigned) of PIM roles
        $EligiblePIMRoles = Invoke-MgGraphRequest -Uri "beta/roleManagement/directory/roleEligibilitySchedules?`$expand=*" -OutputType PSObject | Select -Expand Value
        $AssignedPIMRoles = Invoke-MgGraphRequest -Uri "beta/roleManagement/directory/roleAssignmentSchedules?`$expand=*" -OutputType PSObject | Select -Expand Value
        $DirectoryRoles = $EligiblePIMRoles + $AssignedPIMRoles
        $DirectoryRoleUsers = $DirectoryRoles | Where { $_.Principal.'@odata.type' -eq "#microsoft.graph.user" }
        $RoleMembers = $DirectoryRoleUsers.Principal.userPrincipalName | Select-Object -Unique
    }
    else {
        #Get all members or directory roles
        $DirectoryRoles = Invoke-MgGraphRequest -Uri "/beta/directoryRoles?" -OutputType PSObject | Select -Expand Value
        $RoleMembers = $DirectoryRoles | ForEach-Object { Invoke-MgGraphRequest -uri "/beta/directoryRoles/$($_.id)/members" -OutputType PSObject | Select -Expand Value } | where { $_.'@odata.type' -eq "#microsoft.graph.user" } | Select-Object -expand userPrincipalName -Unique
    }
    $PrivilegedUserRegistrationDetails = $userRegistrationsReport | where { $RoleMembers -contains $_.userPrincipalName }
    Return $PrivilegedUserRegistrationDetails
}

###Method types array
$AllMethods = @(
    [pscustomobject]@{type = 'microsoftAuthenticatorPasswordless'; Name = 'Microsoft Authenticator Passwordless'; Strength = 'Strong' }
    [pscustomobject]@{type = 'fido2SecurityKey'; AltName = 'Fido2'; Name = 'Fido2 Security Key'; Strength = 'Strong' }
    [pscustomobject]@{type = 'passKeyDeviceBound'; AltName = 'Fido2'; Name = 'Device Bound Passkey'; Strength = 'Strong' }
    [pscustomobject]@{type = 'passKeyDeviceBoundAuthenticator'; AltName = 'Fido2'; Name = 'Microsoft Authenticator Passkey'; Strength = 'Strong' }
    [pscustomobject]@{type = 'passKeyDeviceBoundWindowsHello'; AltName = 'Fido2'; Name = 'Windows Hello Passkey'; Strength = 'Strong' }
    [pscustomobject]@{type = 'microsoftAuthenticatorPush'; AltName = 'MicrosoftAuthenticator'; Name = 'Microsoft Authenticator App'; Strength = 'Strong' }
    [pscustomobject]@{type = 'softwareOneTimePasscode'; AltName = 'SoftwareOath'; Name = 'Software OTP'; Strength = 'Strong' }
    [pscustomobject]@{type = 'hardwareOneTimePasscode'; AltName = 'HardwareOath'; Name = 'Hardware OTP'; Strength = 'Strong' }
    [pscustomobject]@{type = 'windowsHelloForBusiness'; AltName = 'windowsHelloForBusiness'; Name = 'Windows Hello for Business'; Strength = 'Strong' }
    [pscustomobject]@{type = 'temporaryAccessPass'; AltName = 'TemporaryAccessPass'; Name = 'Temporary Access Pass'; Strength = 'Strong' }
    [pscustomobject]@{type = 'macOsSecureEnclaveKey'; Name = 'MacOS Secure Enclave Key'; Strength = 'Strong' }
    [pscustomobject]@{type = 'SMS'; AltName = 'SMS'; Name = 'SMS'; Strength = 'Weak' }
    [pscustomobject]@{type = 'Voice Call'; AltName = 'voice'; Name = 'Voice Call'; Strength = 'Weak' }
    [pscustomobject]@{type = 'email'; AltName = 'Email'; Name = 'Email'; Strength = 'Weak' }
    [pscustomobject]@{type = 'alternateMobilePhone'; AltName = 'Voice'; Name = 'Alternative Mobile Phone'; Strength = 'Weak' }
    [pscustomobject]@{type = 'securityQuestion'; AltName = 'Security Questions'; Name = 'Security Questions'; Strength = 'Weak' }
)
$strongMethodTypes = $AllMethods | Where-Object { $_.Strength -eq 'Strong' } | Select-Object -ExpandProperty type
$weakMethodTypes = $AllMethods | Where-Object { $_.Strength -eq 'Weak' }

###Get authentication methods info
#Get user registration details
Write-output "Fetching users registration details..."
$userRegistrationsReport = Get-UserRegistrationDetails
#Get authentication methods
Write-output "Fetching authentication methods..."
$authenticationMethods = Get-AuthenticationMethods
#Get disabled and enabled authentication methods
$disabledAuthenticationMethods = $authenticationMethods | where { $_.State -eq "Disabled" }
$enabledAuthenticationMethods = $authenticationMethods | where { $_.State -eq "Enabled" }
#Get methods enabled and disabled by policy
$MethodsDisabledByPolicy = $AllMethods | Where { $_.AltName -in $disabledAuthenticationMethods.DisplayName }
$MethodsEnabledByPolicy = $AllMethods | Where { $_.AltName -in $enabledAuthenticationMethods.DisplayName }
#get weak authentication methods and count
$enabledWeakAuthenticationMethods = $MethodsEnabledByPolicy | where { $_.Strength -eq "Weak" }

###Calculate totals
#Total number of users
$totalUsersCount = $userRegistrationsReport.Count

### Calculate MFA capable info
Write-output "Analyzing MFA info..."
$totalMFACapableUsers = $userRegistrationsReport | where { $_.isMfaCapable -eq $true }
$totalMFACapableUsersCount = $totalMFACapableUsers.Count
#Calculate percentage of MFA capable users
$MfaCapablePercentage = 0
if ($totalUsersCount -gt 0) {
    $MfaCapablePercentage = [math]::Round(($totalMFACapableUsersCount / $totalUsersCount) * 100, 2)
}

###Calculate passwordless info
Write-output "Analyzing passwordless info..."
$totalPasswordlessUsers = $userRegistrationsReport | where { $_.isPasswordlessCapable -eq $true }
$totalPasswordlessUsersCount = $totalPasswordlessUsers.Count
#Calculate percentage of passwordless capable users
$passwordlessCapablePercentage = 0
if ($totalUsersCount -gt 0) {
    $passwordlessCapablePercentage = [math]::Round(($totalPasswordlessUsersCount / $totalUsersCount) * 100, 2)
}

###Calculate strong authentication method info
# Filter users who have registered strong authentication methods
Write-output "Analyzing users who have registered strong authentication methods..."
$usersWithStrongMethods = $userRegistrationsReport | Where-Object {
    $user = $_
    # Check if any of the user's registered methods are in the strongMethodTypes list
    if ($user.methodsRegistered) {
        foreach ($method in $user.methodsRegistered) {
            if ($strongMethodTypes -contains $method) {
                return $true
            }
        }
    }
    return $false
}
#Calculate counts and percentages
$totalStrongAuthUsersCount = $usersWithStrongMethods.Count
$strongAuthPercentage = 0
if ($totalUsersCount -gt 0) {
    $strongAuthPercentage = [math]::Round(($totalStrongAuthUsersCount / $totalUsersCount) * 100, 2)
}

###Calculate weak authentication method info
# Filter users who have ONLY weak authentication methods registered
Write-output "Analyzing users who have ONLY weak authentication methods registered..."
$usersWithWeakMethods = $userRegistrationsReport | Where-Object {
    $user = $_
    # Check if any of the user's registered methods are in the weakMethodTypes list
    if ($user.methodsRegistered) {
        foreach ($method in $user.methodsRegistered) {
            if ($weakMethodTypes.type -contains $method) {
                return $true
            }
        }
    }
    return $false
}

###Calculate users with both strong AND weak methods
Write-output "Analyzing users with both strong AND weak methods..."
$usersWithBothMethodTypes = $usersWithStrongMethods | Where-Object {
    $user = $_
    # Check if this user is also in the weak methods list by comparing UPN
    $usersWithWeakMethods.userPrincipalName -contains $user.userPrincipalName
}
# Calculate counts and percentages
$totalBothMethodTypesCount = $usersWithBothMethodTypes.Count
$bothMethodsPercentage = 0
if ($totalUsersCount -gt 0) {
    $bothMethodsPercentage = [math]::Round(($totalBothMethodTypesCount / $totalUsersCount) * 100, 2)
}

### Calculate privileged users not using phish resistant methods methods
Write-output "Analyzing privileged users not using phish resistant methods..."
$PrivilegedUsersRegistrationDetails = Get-PrivilegedUserRegistrationDetails -userRegistrations $userRegistrationsReport
$PrivilegedUsersNotUsingPhishResistantMethods = $PrivilegedUsersRegistrationDetails | where { $_.methodsRegistered -notcontains "fido2SecurityKey" -and $_.methodsRegistered -notcontains "passKeyDeviceBound" -and $_.methodsRegistered -notcontains "passKeyDeviceBoundAuthenticator" }
# Count of privileged users not using phish resistant methods
$PrivilegedUsersNotUsingPhishResistantMethodsCount = $PrivilegedUsersNotUsingPhishResistantMethods.Count

## Generate HTML report
Function Generate-EntraAuthReport {
    param(
        [Parameter(Mandatory = $true)]
        [array]$UserRegistrations,
        
        [Parameter(Mandatory = $true)]
        [array]$MethodTypes,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "C:\GitHub\Private\Reports\EntraAuthenticationReport.html"
    )
    
    # Create HTML header
    $html = [System.Text.StringBuilder]::new()

    [void]$html.AppendLine(@"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Entra Authentication Methods Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            color: #333;
        }
        .header-container {
            background: linear-gradient(135deg, #0078D4 0%, #106EBE 100%);
            color: white;
            padding: 25px 40px;
            margin-bottom: 30px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        h1 {
            font-size: 28px;
            font-weight: 600;
            margin: 0;
            letter-spacing: -0.5px;
        }
        .header-subtitle {
            font-size: 14px;
            font-weight: 400;
            margin-top: 0px;
            margin-bottom: 10px;
            opacity: 0.9;
        }
        .author-info {
            margin-top: 12px;
            border-top: 1px solid rgba(255, 255, 255, 0.3);
            padding-top: 10px;
            display: flex;
            align-items: center;
            font-size: 13px;
        }
        .author-label {
            opacity: 0.8;
            margin-right: 6px;
        }
        .author-links {
            display: flex;
            align-items: center;
        }
        .author-link {
            color: white;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            border: 1px solid rgba(255, 255, 255, 0.5);
            padding: 4px 10px;
            border-radius: 4px;
            margin-right: 10px;
            transition: all 0.2s ease;
            background-color: rgba(255, 255, 255, 0.1);
        }
        .author-link:hover {
            background-color: rgba(255, 255, 255, 0.2);
            border-color: rgba(255, 255, 255, 0.7);
        }
        .author-link svg {
            margin-right: 5px;
        }
        .report-info {
            text-align: right;
            font-size: 14px;
        }
        .report-date {
            font-weight: 500;
            margin-top: 5px;
        }
        .content-container {
            max-width: 1550px;
            margin: 0 auto;
            padding: 0 20px 40px;
        }
        /* Progress bar styling */
        .progress-container {
            width: 100%;
            background-color: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            box-sizing: border-box; /* Add this to include padding in the width calculation */
        }
        .progress-title {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 15px;
            color: #333;
        }
        .progress-bar-container {
            height: 30px;
            width: 100%;
            background-color: #e0e0e0;
            border-radius: 15px;
            overflow: hidden;
            position: relative;
        }
        .progress-bar {
            height: 100%;
            background: linear-gradient(135deg, #0078D4 0%, #57A773 100%);
            border-radius: 15px;
            transition: width 1s ease-in-out;
        }
        .progress-text {
            position: absolute;
            top: 0;
            left: 0;
            height: 100%;
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.2);
        }
        .progress-info {
            display: flex;
            justify-content: space-between;
            margin-top: 10px;
            font-size: 14px;
            color: #666;
        }
        .progress-legend {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            margin-top: 15px;
            gap: 20px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            font-size: 13px;
        }
        .legend-color {
            width: 15px;
            height: 15px;
            margin-right: 5px;
            border-radius: 2px;
        }
        .summary-stats {
            display: flex;
            flex-wrap: wrap;
            margin-bottom: 30px;
            gap: 20px;
        }
        .stat-card {
            background-color: white;
            border-radius: 8px;
            padding: 20px;
            flex: 1;
            min-width: 200px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }
        .stat-title {
            font-size: 14px;
            color: #666;
            margin-bottom: 10px;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #0078D4;
        }
        .stat-percentage {
            font-size: 14px;
            color: #666;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background-color: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: none; /* Remove duplicate shadow */
            margin-bottom: 0; /* Remove margin from table as container has margin */
            table-layout: fixed; /* Add fixed table layout for better column width control */
        }
        th {
            background-color: #0078D4;
            color: white;
            text-align: center;
            padding: 10px 5px;
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
            font-size: 12px;
            height: auto; /* Auto height instead of fixed 80px */
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: normal; /* Allow text to wrap */
            hyphens: auto; /* Enable hyphenation */
            word-break: break-word;
        }
        /* Remove diagonal styling and simplify headers */
        th.diagonal-header {
            position: relative;
            text-align: center;
            padding: 10px 5px;
        }
        th.diagonal-header > div {
            position: static; /* Regular positioning instead of absolute */
            transform: none; /* Remove rotation */
            width: auto;
            white-space: normal; /* Allow text to wrap */
            font-size: 11px;
            padding: 0;
        }
        th.strong-method {
            background-color: #57A773;
        }
        th.weak-method {
            background-color: #EE6352;
        }
        td {
            padding: 10px 15px;
            border-bottom: 1px solid #eee;
            overflow: hidden;
            text-overflow: ellipsis; /* Add ellipsis for overflowing cell content */
            white-space: nowrap; /* Prevent text wrapping in cells */
            text-align: center; /* Center cell content */
        }
        td:first-child {
            text-align: left; /* Left align the UPN column */
        }
        tr:last-child td {
            border-bottom: none;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        tr:hover {
            background-color: #f1f1f1;
        }
        /* Style for the table container to enable horizontal scrolling on small screens */
        .table-container {
            width: 100%; /* Reset to 100% from 120% */
            overflow-x: auto;
            margin-bottom: 30px;
            margin-left: 0; /* Reset margin-left from -120px */
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
            border-radius: 8px;
            position: relative; /* Keep relative positioning */
        }
        
        /* Style for expand icon - now positioned as a filter button */
        .expand-icon {
            padding: 8px 15px;
            background-color: #eee;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin-left: auto; /* Push to right side of filter container */
        }
        
        .expand-icon:hover {
            background-color: #ddd;
        }
        
        .expand-icon svg {
            width: 16px;
            height: 16px;
            margin-right: 5px;
        }
        
        /* Add tooltip capability for truncated text */
        td[title], th[title] {
            cursor: pointer;
        }
        
        /* Media query for responsive design */
        @media (max-width: 768px) {
            .table-container {
                margin-bottom: 20px;
            }
        }
        .method-registered {
            color: #107C10;
            text-align: center;
            font-weight: bold;
        }
        .method-not-registered {
            color: #D83B01;
            text-align: center;
        }
        .strong-method {
            background-color:#57A773; /* Darker green background */
        }
        .weak-method {
            background-color: #EE6352; /* Darker red/pink background */
        }
        .search-container {
            margin-bottom: 20px;
        }
        #searchBox {
            padding: 10px;
            width: 300px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        .filter-container {
            display: flex;
            margin-bottom: 20px;
            gap: 15px;
            flex-wrap: wrap;
        }
        .filter-button {
            padding: 8px 15px;
            background-color: #eee;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.2s;
        }
        .filter-button:hover {
            background-color: #ddd;
        }
        .filter-button.active {
            background-color: #0078D4;
            color: white;
        }
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 12px;
        }
        .checkmark {
            color: #0a5a0a; /* Darker green for checkmarks */
            font-size: 18px;
            font-weight: bold;
        }
        .x-mark {
            color: #b92e02; /* Darker red for x-marks */
            font-size: 18px;
            font-weight: bold;
        }
        .switch-container {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
        }
        .switch {
            position: relative;
            display: inline-block;
            width: 60px;
            height: 30px;
            margin-right: 10px;
        }
        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #ccc;
            transition: .4s;
            border-radius: 30px;
        }
        .slider:before {
            position: absolute;
            content: "";
            height: 22px;
            width: 22px;
            left: 4px;
            bottom: 4px;
            background-color: white;
            transition: .4s;
            border-radius: 50%;
        }
        input:checked + .slider {
            background-color: #0078D4;
        }
        input:checked + .slider:before {
            transform: translateX(30px);
        }
        .switch-label {
            font-size: 14px;
        }
        /* Remove the old button style */
        .hide-disabled-btn {
            display: none;
        }
        /* Style for switch group container */
        .switches-group {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 20px;
        }
        /* Add data attribute styling for sync users */
        [data-syncuser='true'] {
            /* No specific styling needed as we'll just hide them with JS */
        }
        
        /* Modal styles for fullscreen table */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.8);
            z-index: 1000;
            overflow: auto;
        }
        
        .modal-content {
            background-color: white;
            margin: 2% auto;
            padding: 20px;
            width: 95%;
            max-width: none;
            border-radius: 8px;
            position: relative;
        }
        
        .close-modal {
            color: #666;
            position: absolute;
            top: 15px;
            right: 15px;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            z-index: 1001;
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            background-color: #f0f0f0;
            transition: all 0.2s ease;
        }
        
        .close-modal:hover {
            background-color: #e0e0e0;
            color: #333;
        }
        
        /* Fullscreen table styles */
        .fullscreen-table-container {
            width: 100%;
            overflow-x: auto;
        }
        
        .fullscreen-table-container table {
            width: 100%;
            table-layout: auto; /* Override fixed layout for fullscreen */
        }
        
        .fullscreen-table-container th,
        .fullscreen-table-container td {
            white-space: normal; /* Allow text wrapping in fullscreen mode */
        }
        
        body.modal-open {
            overflow: hidden; /* Prevent scrolling of background when modal is open */
        }

        /* Style for export button - similar to expand icon */
        .export-csv-button {
            padding: 8px 15px;
            background-color: #eee;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin-left: auto; /* Push to right side of filter container */
            margin-right: 10px; /* Add space between export and expand buttons */
        }
        
        .export-csv-button:hover {
            background-color: #ddd;
        }
        
        .export-csv-button svg {
            width: 16px;
            height: 16px;
            margin-right: 5px;
        }
        
        /* Additional styles for the expand icon to work with the new button */
        .expand-icon {
            /* Existing styles */
            margin-left: 0; /* Remove auto margin since we're using flexbox spacing */
        }

        /* Add space to separate buttons from filter buttons */
        .button-group {
            margin-left: auto;
            display: flex;
        }
        
        /* Update filter container to use flexbox properly */
        .filter-container {
            display: flex;
            margin-bottom: 20px;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
    </style>
    <!-- Add FileSaver.js for better file saving experience -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/FileSaver.js/2.0.5/FileSaver.min.js"></script>
</head>
<body>
    <div class="header-container">
        <div class="header-content">
            <div>
                <h1>Microsoft Entra Authentication Methods Report</h1>
                <div class="header-subtitle">Overview of authentication methods registered by users</div>
                <div class="author-info">
                    <span class="author-label">Created by:</span>
                    <div class="author-links">
                        <a href="https://www.linkedin.com/in/danielbradley2/" class="author-link" target="_blank">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="white">
                                <path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z"/>
                            </svg>
                            Daniel Bradley
                        </a>
                        <a href="https://ourcloudnetwork.com" class="author-link" target="_blank">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="white">
                                <path d="M21 13v10h-21v-19h12v2h-10v15h17v-8h2zm3-12h-10.988l4.035 4-6.977 7.07 2.828 2.828 6.977-7.07 4.125 4.172v-11z"/>
                            </svg>
                            ourcloudnetwork.com
                        </a>
                    </div>
                </div>
            </div>
            <div class="report-info">
                <div class="report-date">Generated: $(Get-Date -Format "MMMM d, yyyy")</div>
                <div class="tenant">Org: $organisationName</div>
            </div>
        </div>
    </div>
    <div class="content-container">
        <!-- Add progress bar section -->
        <div class="progress-container" style="max-width: 100%; margin-bottom: 30px;">
            <div class="progress-title">Progress Towards Passwordless Authentication</div>
            <div class="progress-bar-container">
                <div class="progress-bar" style="width: $($passwordlessCapablePercentage)%"></div>
                <div class="progress-text">$passwordlessCapablePercentage% Complete</div>
            </div>
            <div class="progress-info">
                <span>0%</span>
                <span>Target: 100% of users passwordless capable</span>
                <span>100%</span>
            </div>
            <div class="progress-legend">
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #57A773;"></div>
                    <span>$totalPasswordlessUsersCount users passwordless capable</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: #e0e0e0;"></div>
                    <span>$($totalUsersCount - $totalPasswordlessUsersCount) users still need passwordless capability</span>
                </div>
            </div>
        </div>

        <div class="summary-stats">
            <div class="stat-card">
                <div class="stat-title">Total Users</div>
                <div class="stat-value">$totalUsersCount</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">MFA Capable Users</div>
                <div class="stat-value">$totalMFACapableUsersCount</div>
                <div class="stat-percentage">$MfaCapablePercentage% of users</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Strong Auth Methods</div>
                <div class="stat-value">$totalStrongAuthUsersCount</div>
                <div class="stat-percentage">$strongAuthPercentage% of users</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Passwordless Capable</div>
                <div class="stat-value">$totalPasswordlessUsersCount</div>
                <div class="stat-percentage">$passwordlessCapablePercentage% of users</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Strong + Weak Auth</div>
                <div class="stat-value">$totalBothMethodTypesCount</div>
                <div class="stat-percentage">$bothMethodsPercentage% of users</div>
            </div>
        </div>

        <div class="search-container">
            <input type="text" id="searchBox" placeholder="Search for a user..." onkeyup="searchTable()">
        </div>
        
        <div class="switches-group">
            <div class="switch-container">
                <label class="switch">
                    <input type="checkbox" id="hideDisabledSwitch" onchange="toggleDisabledMethods()">
                    <span class="slider"></span>
                </label>
                <span class="switch-label">Hide Disabled Authentication Methods</span>
            </div>
            
            <div class="switch-container">
                <label class="switch">
                    <input type="checkbox" id="hideMfaCapableSwitch" onchange="toggleMfaCapableUsers()">
                    <span class="slider"></span>
                </label>
                <span class="switch-label">Hide MFA Capable Users</span>
            </div>
            
            <div class="switch-container">
                <label class="switch">
                    <input type="checkbox" id="hideETXUsersSwitch" onchange="toggleETXUsers()">
                    <span class="slider"></span>
                </label>
                <span class="switch-label">Hide External Users</span>
            </div>
            
            <div class="switch-container">
                <label class="switch">
                    <input type="checkbox" id="hideSyncUsersSwitch" onchange="toggleSyncUsers()">
                    <span class="slider"></span>
                </label>
                <span class="switch-label">Hide Sync_ Account</span>
            </div>
        </div>
        
        <div class="filter-container">
            <button class="filter-button active" onclick="filterTable('all')">All Users</button>
            <button class="filter-button" onclick="filterTable('privileged')">Privileged Users</button>
            <button class="filter-button" onclick="filterTable('passwordless')">Passwordless Capable</button>
            <button class="filter-button" onclick="filterTable('strong')">Strong Methods</button>
            <button class="filter-button" onclick="filterTable('mixed')">Strong+Weak Methods</button>
            <button class="filter-button" onclick="filterTable('weak')">Weak Methods Only</button>
            <div class="button-group">
                <button class="export-csv-button" onclick="exportTableToCSV()" title="Export table to CSV file">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"></path>
                        <polyline points="7 10 12 15 17 10"></polyline>
                        <line x1="12" y1="15" x2="12" y2="3"></line>
                    </svg>
                    Export CSV
                </button>
                <button class="expand-icon" onclick="openFullscreenTable()" title="Expand table to full screen">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"></path>
                    </svg>
                    Expand
                </button>
            </div>
        </div>

        <div class="table-container">
            <table id="authMethodsTable">
                <thead>
                    <tr>
                        <th style="width: 14%;">User Principal Name</th>
                        <th style="width: 7%;">Default Method</th>
                        <th style="width: 5%;">MFA</th>
                        <th style="width: 5%;">Pless</th>
"@)

    # Add column for each method type
    foreach ($method in $MethodTypes) {
        $cssClass = if ($method.Strength -eq "Strong") { "strong-method" } else { "weak-method" }
        
        # Check if this method is disabled by policy
        $isDisabled = $MethodsDisabledByPolicy.Name -contains $method.Name
        
        if ($isDisabled) {
            [void]$html.AppendLine("                    <th class=`"$cssClass diagonal-header`" data-disabled=`"true`"><div>$($method.Name)</div></th>`n")
        }
        else {
            [void]$html.AppendLine("                    <th class=`"$cssClass diagonal-header`" ><div>$($method.Name)</div></th>`n")
        }
    }

    [void]$html.AppendLine(@"
                </tr>
            </thead>
            <tbody>
"@)

    # Add a row for each user
    foreach ($user in $UserRegistrations) {
        $userMethods = $user.methodsRegistered
        $userHasStrong = $false
        $userHasWeak = $false
        $isPrivileged = $false
        $isSyncUser = $false
        
        # Check if user has strong or weak methods
        foreach ($method in $userMethods) {
            if ($strongMethodTypes -contains $method) {
                $userHasStrong = $true
            }
            if ($weakMethodTypes.type -contains $method) {
                $userHasWeak = $true
            }
        }
        
        # Check if user is privileged
        if ($PrivilegedUsersRegistrationDetails.userPrincipalName -contains $user.userPrincipalName) {
            $isPrivileged = $true
        }

        # Check if user is a sync user
        if (($user.userPrincipalName -like "Sync_*") -or ($user.userPrincipalName -like "ADToAADSyncServiceAccount*")) {
            $isSyncUser = $true
        }
        
        # Set data attribute for filtering
        $dataAttributes = ""
        if ($userHasStrong) { $dataAttributes += "data-hasstrong='true' " }
        if ($userHasWeak -and -not $userHasStrong) { $dataAttributes += "data-weakonly='true' " }
        if ($userHasStrong -and $userHasWeak) { $dataAttributes += "data-mixed='true' " }
        if ($user.isPasswordlessCapable) { $dataAttributes += "data-passwordless='true' " }
        if ($user.isMfaCapable) { $dataAttributes += "data-mfacapable='true' " }
        if ($user.userPrincipalName -like "*#EXT#*") { $dataAttributes += "data-externaluser='true' " }
        if ($isPrivileged) { $dataAttributes += "data-privileged='true' " }
        if ($isSyncUser) { $dataAttributes += "data-syncuser='true' " }
        
        [void]$html.AppendLine("                <tr $dataAttributes>`n")
        [void]$html.AppendLine("                    <td>$($user.userPrincipalName)</td>`n")
        [void]$html.AppendLine("                    <td>$($user.defaultmfaMethod)</td>`n")
        [void]$html.AppendLine("                    <td>$(if($user.isMfaCapable) {"<span class='checkmark'>✓</span>"} else {"<span class='x-mark'>✗</span>"})</td>`n")
        [void]$html.AppendLine("                    <td>$(if($user.isPasswordlessCapable) {"<span class='checkmark'>✓</span>"} else {"<span class='x-mark'>✗</span>"})</td>`n")
        
        # Add column for each method type - check if registered
        foreach ($method in $MethodTypes) {
            $isRegistered = $userMethods -contains $method.type
            [void]$html.AppendLine("                    <td>$(if($isRegistered) {"<span class='checkmark'>✓</span>"} else {"<span class='x-mark'>✗</span>"})</td>`n")
        }
        
        [void]$html.AppendLine("                </tr>`n")
    }

    [void]$html.AppendLine(@"
            </tbody>
        </table>
    </div>
        
    <!-- Modal for fullscreen table -->
    <div id="tableModal" class="modal">
        <div class="modal-content">
            <span class="close-modal" onclick="closeFullscreenTable()">&times;</span>
            <h2>Authentication Methods - Expanded View</h2>
            <div class="fullscreen-table-container">
                <!-- The table will be cloned here via JavaScript -->
            </div>
        </div>
    </div>

    <div class="footer">
        <p>Authentication Methods report generated via Microsoft Graph API | $organisationName</p>
    </div>

    <script>
        // Initialize counters for dynamic updates
        let totalUsers = $totalUsersCount;
        let mfaCapableUsers = $totalMFACapableUsersCount;
        let strongAuthUsers = $totalStrongAuthUsersCount;
        let passwordlessUsers = $totalPasswordlessUsersCount;
        let mixedAuthUsers = $totalBothMethodTypesCount;
        
        // Store external user counts for recalculation
        let externalUserCounts = {
            total: 0,
            mfaCapable: 0,
            strongAuth: 0,
            passwordless: 0,
            mixedAuth: 0
        };
        
        // Store sync user counts for recalculation
        let syncUserCounts = {
            total: 0,
            mfaCapable: 0,
            strongAuth: 0,
            passwordless: 0,
            mixedAuth: 0
        };
        
        // After page loads, count external users
        document.addEventListener('DOMContentLoaded', function() {
            const table = document.getElementById('authMethodsTable');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                if (row.hasAttribute('data-externaluser')) {
                    externalUserCounts.total++;
                    if (row.hasAttribute('data-mfacapable')) externalUserCounts.mfaCapable++;
                    if (row.hasAttribute('data-hasstrong')) externalUserCounts.strongAuth++;
                    if (row.hasAttribute('data-passwordless')) externalUserCounts.passwordless++;
                    if (row.hasAttribute('data-mixed')) externalUserCounts.mixedAuth++;
                }
                
                if (row.hasAttribute('data-syncuser')) {
                    syncUserCounts.total++;
                    if (row.hasAttribute('data-mfacapable')) syncUserCounts.mfaCapable++;
                    if (row.hasAttribute('data-hasstrong')) syncUserCounts.strongAuth++;
                    if (row.hasAttribute('data-passwordless')) syncUserCounts.passwordless++;
                    if (row.hasAttribute('data-mixed')) syncUserCounts.mixedAuth++;
                }
            }
        });
        
        // Update all summary cards and progress bar
        function updateSummaryStats(hideExternal, hideSync) {
            // Calculate adjusted counts
            let adjustedTotal = totalUsers;
            let adjustedMfa = mfaCapableUsers;
            let adjustedStrong = strongAuthUsers;
            let adjustedPasswordless = passwordlessUsers;
            let adjustedMixed = mixedAuthUsers;
            
            // Subtract external users if they're hidden
            if (hideExternal) {
                adjustedTotal -= externalUserCounts.total;
                adjustedMfa -= externalUserCounts.mfaCapable;
                adjustedStrong -= externalUserCounts.strongAuth;
                adjustedPasswordless -= externalUserCounts.passwordless;
                adjustedMixed -= externalUserCounts.mixedAuth;
            }
            
            // Subtract sync users if they're hidden
            if (hideSync) {
                adjustedTotal -= syncUserCounts.total;
                adjustedMfa -= syncUserCounts.mfaCapable;
                adjustedStrong -= syncUserCounts.strongAuth;
                adjustedPasswordless -= syncUserCounts.passwordless;
                adjustedMixed -= syncUserCounts.mixedAuth;
            }
            
            // Calculate percentages
            const mfaPercentage = adjustedTotal > 0 ? Math.round((adjustedMfa / adjustedTotal) * 100 * 100) / 100 : 0;
            const strongPercentage = adjustedTotal > 0 ? Math.round((adjustedStrong / adjustedTotal) * 100 * 100) / 100 : 0;
            const passwordlessPercentage = adjustedTotal > 0 ? Math.round((adjustedPasswordless / adjustedTotal) * 100 * 100) / 100 : 0;
            const mixedPercentage = adjustedTotal > 0 ? Math.round((adjustedMixed / adjustedTotal) * 100 * 100) / 100 : 0;
            
            // Update summary cards
            document.querySelector('.stat-card:nth-child(1) .stat-value').textContent = adjustedTotal;
            
            document.querySelector('.stat-card:nth-child(2) .stat-value').textContent = adjustedMfa;
            document.querySelector('.stat-card:nth-child(2) .stat-percentage').textContent = mfaPercentage + '% of users';
            
            document.querySelector('.stat-card:nth-child(3) .stat-value').textContent = adjustedStrong;
            document.querySelector('.stat-card:nth-child(3) .stat-percentage').textContent = strongPercentage + '% of users';
            
            document.querySelector('.stat-card:nth-child(4) .stat-value').textContent = adjustedPasswordless;
            document.querySelector('.stat-card:nth-child(4) .stat-percentage').textContent = passwordlessPercentage + '% of users';
            
            document.querySelector('.stat-card:nth-child(5) .stat-value').textContent = adjustedMixed;
            document.querySelector('.stat-card:nth-child(5) .stat-percentage').textContent = mixedPercentage + '% of users';
            
            // Update progress bar
            const progressBar = document.querySelector('.progress-bar');
            const progressText = document.querySelector('.progress-text');
            const passwordlessLegend = document.querySelector('.legend-item:first-child span');
            const nonPasswordlessLegend = document.querySelector('.legend-item:last-child span');
            
            progressBar.style.width = passwordlessPercentage + '%';
            progressText.textContent = passwordlessPercentage + '% Complete';
            passwordlessLegend.textContent = adjustedPasswordless + ' users passwordless capable';
            nonPasswordlessLegend.textContent = (adjustedTotal - adjustedPasswordless) + ' users still need passwordless capability';
        }

        function searchTable() {
            const input = document.getElementById('searchBox');
            const filter = input.value.toUpperCase();
            const table = document.getElementById('authMethodsTable');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const firstCol = rows[i].getElementsByTagName('td')[0];
                if (firstCol) {
                    const txtValue = firstCol.textContent || firstCol.innerText;
                    if (txtValue.toUpperCase().indexOf(filter) > -1) {
                        rows[i].style.display = '';
                    } else {
                        rows[i].style.display = 'none';
                    }
                }
            }
        }
        
        function filterTable(filterType) {
            const buttons = document.querySelectorAll('.filter-button');
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            const table = document.getElementById('authMethodsTable');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                
                if (filterType === 'all') {
                    row.style.display = '';
                } else if (filterType === 'strong' && row.hasAttribute('data-hasstrong')) {
                    row.style.display = '';
                } else if (filterType === 'weak' && row.hasAttribute('data-weakonly')) {
                    row.style.display = '';
                } else if (filterType === 'passwordless' && row.hasAttribute('data-passwordless')) {
                    row.style.display = '';
                } else if (filterType === 'mixed' && row.hasAttribute('data-mixed')) {
                    row.style.display = '';
                } else if (filterType === 'privileged' && row.hasAttribute('data-privileged')) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            }
        }
        
        function toggleDisabledMethods() {
            const switchElem = document.getElementById('hideDisabledSwitch');
            const isHiding = switchElem.checked;
            
            // Get all table headers and find disabled ones
            const table = document.getElementById('authMethodsTable');
            const headers = table.getElementsByTagName('th');
            
            // Loop through all headers to find disabled methods
            for (let i = 0; i < headers.length; i++) {
                if (headers[i].hasAttribute('data-disabled')) {
                    // Hide/show the header
                    headers[i].style.display = isHiding ? 'none' : '';
                    
                    // Hide/show the corresponding cell in each row
                    const rows = table.getElementsByTagName('tr');
                    for (let j = 1; j < rows.length; j++) {
                        const cells = rows[j].getElementsByTagName('td');
                        if (i < cells.length) {
                            cells[i].style.display = isHiding ? 'none' : '';
                        }
                    }
                }
            }
        }
        
        function toggleMfaCapableUsers() {
            const switchElem = document.getElementById('hideMfaCapableSwitch');
            const isHiding = switchElem.checked;
            
            // Get all table rows
            const table = document.getElementById('authMethodsTable');
            const rows = table.getElementsByTagName('tr');
            
            // Skip header row (i=0) and process all data rows
            for (let i = 1; i < rows.length; i++) {
                if (rows[i].hasAttribute('data-mfacapable')) {
                    rows[i].style.display = isHiding ? 'none' : '';
                }
            }
        }
        
        function toggleETXUsers() {
            const switchElem = document.getElementById('hideETXUsersSwitch');
            const isHiding = switchElem.checked;
            const syncUserElem = document.getElementById('hideSyncUsersSwitch');
            const hidingSync = syncUserElem ? syncUserElem.checked : false;
            
            // Get all table rows
            const table = document.getElementById('authMethodsTable');
            const rows = table.getElementsByTagName('tr');
            
            // Skip header row (i=0) and process all data rows
            for (let i = 1; i < rows.length; i++) {
                if (rows[i].hasAttribute('data-externaluser')) {
                    rows[i].style.display = isHiding ? 'none' : '';
                }
            }
            
            // Update the summary cards and progress bar
            updateSummaryStats(isHiding, hidingSync);
        }
        
        function toggleSyncUsers() {
            const switchElem = document.getElementById('hideSyncUsersSwitch');
            const isHiding = switchElem.checked;
            const extUserElem = document.getElementById('hideETXUsersSwitch');
            const hidingExt = extUserElem ? extUserElem.checked : false;
            
            // Get all table rows
            const table = document.getElementById('authMethodsTable');
            const rows = table.getElementsByTagName('tr');
            
            // Skip header row (i=0) and process all data rows
            for (let i = 1; i < rows.length; i++) {
                if (rows[i].hasAttribute('data-syncuser')) {
                    rows[i].style.display = isHiding ? 'none' : '';
                }
            }
            
            // Update the summary cards and progress bar
            updateSummaryStats(hidingExt, isHiding);
        }
        
        // Functions for fullscreen table view
        function openFullscreenTable() {
            const modal = document.getElementById('tableModal');
            const originalTable = document.getElementById('authMethodsTable');
            const fullscreenContainer = document.querySelector('.fullscreen-table-container');
            
            // Clone the table for the modal
            const clonedTable = originalTable.cloneNode(true);
            clonedTable.id = 'fullscreenTable';
            
            // Clear previous content and add the cloned table
            fullscreenContainer.innerHTML = '';
            fullscreenContainer.appendChild(clonedTable);
            
            // Show the modal
            modal.style.display = 'block';
            document.body.classList.add('modal-open');
            
            // Apply any active filters to the cloned table
            applyActiveFiltersToFullscreenTable();
        }
        
        function closeFullscreenTable() {
            const modal = document.getElementById('tableModal');
            modal.style.display = 'none';
            document.body.classList.remove('modal-open');
        }
        
        function applyActiveFiltersToFullscreenTable() {
            // Get all visible/hidden rows from the original table
            const originalTable = document.getElementById('authMethodsTable');
            const fullscreenTable = document.getElementById('fullscreenTable');
            
            if (!originalTable || !fullscreenTable) return;
            
            const originalRows = originalTable.getElementsByTagName('tr');
            const fullscreenRows = fullscreenTable.getElementsByTagName('tr');
            
            // Skip header row (i=0) and apply the same visibility to each row
            for (let i = 1; i < originalRows.length && i < fullscreenRows.length; i++) {
                fullscreenRows[i].style.display = originalRows[i].style.display;
            }
            
            // Apply the same column visibility for methods that might be hidden
            const originalHeaders = originalTable.querySelectorAll('th');
            const fullscreenHeaders = fullscreenTable.querySelectorAll('th');
            
            for (let i = 0; i < originalHeaders.length && i < fullscreenHeaders.length; i++) {
                if (originalHeaders[i].style.display === 'none') {
                    fullscreenHeaders[i].style.display = 'none';
                    
                    // Hide corresponding cells in each row
                    for (let j = 1; j < fullscreenRows.length; j++) {
                        const cells = fullscreenRows[j].getElementsByTagName('td');
                        if (i < cells.length) {
                            cells[i].style.display = 'none';
                        }
                    }
                }
            }
        }
        
        // Close modal when clicking outside of it
        window.onclick = function(event) {
            const modal = document.getElementById('tableModal');
            if (event.target === modal) {
                closeFullscreenTable();
            }
        }
        
        // Add event listener to close with Escape key
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape' || event.keyCode === 27) {
                closeFullscreenTable();
            }
        });

        // Function to export table data to CSV
        function exportTableToCSV() {
            // Create a simple CSV string with proper formatting
            let csvContent = [];
            
            // Get the table and header cells
            const table = document.getElementById('authMethodsTable');
            const headerRow = table.querySelector('thead tr');
            const headerCells = headerRow.querySelectorAll('th');
            
            // Create header row for CSV
            let headerCsvRow = [];
            for (let i = 0; i < headerCells.length; i++) {
                if (headerCells[i].style.display !== 'none') {
                    let cellText = headerCells[i].textContent.trim();
                    // Escape double quotes with double quotes for CSV format
                    cellText = cellText.replace(/"/g, '""');
                    headerCsvRow.push('"' + cellText + '"');
                }
            }
            csvContent.push(headerCsvRow.join(','));
            
            // Get all visible rows and process them
            const dataRows = table.querySelectorAll('tbody tr');
            for (let i = 0; i < dataRows.length; i++) {
                if (dataRows[i].style.display === 'none') continue;
                
                let csvRow = [];
                const cells = dataRows[i].querySelectorAll('td');
                
                for (let j = 0; j < cells.length; j++) {
                    if (cells[j].style.display === 'none') continue;
                    
                    let cellText = cells[j].textContent.trim();
                    // Convert checkmarks and x-marks to Yes/No
                    if (cellText === '✓') cellText = 'Yes';
                    if (cellText === '✗') cellText = 'No';
                    
                    // Escape double quotes with double quotes for CSV format
                    cellText = cellText.replace(/"/g, '""');
                    csvRow.push('"' + cellText + '"');
                }
                
                csvContent.push(csvRow.join(','));
            }
            
            // Join all rows with proper newlines
            const csvString = csvContent.join('\r\n');
            
            // Get date for filename
            const today = new Date();
            const date = today.toISOString().split('T')[0]; // YYYY-MM-DD format
            
            // Create download link with data URI
            const downloadLink = document.createElement('a');
            
            // Add BOM for proper UTF-8 encoding in Excel
            const BOM = '\uFEFF';
            const encodedUri = 'data:text/csv;charset=utf-8,' + encodeURIComponent(BOM + csvString);
            
            downloadLink.setAttribute('href', encodedUri);
            downloadLink.setAttribute('download', 'Entra_Auth_Methods_Report_' + date + '.csv');
            document.body.appendChild(downloadLink);
            
            // Trigger download and remove link
            downloadLink.click();
            document.body.removeChild(downloadLink);
        }
        
    </script>
</body>
</html>
"@)

    # Generate the path
    $OutputPath = Join-Path -Path $outpath -ChildPath "Entra_Authentication_Methods_Report.html"

    # Output HTML report
    $html.ToString() | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-output "HTML report generated at $OutputPath"
    
    # Open the report in the default browser
    if ($openbrowser) {
        Start-Process $OutputPath
    }
}

# Generate the report
Write-output "Generating HTML report..."
Generate-EntraAuthReport -UserRegistrations $userRegistrationsReport -MethodTypes $AllMethods -OutputPath $OutputPath
