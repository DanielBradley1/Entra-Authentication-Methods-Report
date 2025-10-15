<#PSScriptInfo

.VERSION 0.5.0

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
    v0.4 - Added limit, skipGuest, skipDetailedPhoneInfo and openBrowser parameters.
    v0.5 - Improved overall performance and UX with high number of users.
#>

<#
.DESCRIPTION 
 This script, created by Daniel Bradley at ourcloudnetwork.co.uk, generates a report on the authentication methods registered by users in your Microsoft 365 tenant. The report includes information on the number of users, the percentage of users with strong authentication methods, the percentage of users who are passwordless capable, and more. The script uses the Microsoft Graph API to retrieve the necessary data and the report is built with HTML, CSS and JS.

.PARAMETER outpath
 Specified the output path of the report file.

.PARAMETER limit
 Defines how many userRegistrationDetails records to fetch.

.PARAMETER skipGuest
 Skip all the users of type 'guest'.

.PARAMETER skipDetailedPhoneInfo
 Skip the request for detailed Mobile authentication methods.

.PARAMETER openBrowser
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
    [switch]$skipGuest = $false,

    [Parameter(Mandatory = $false)]
    [switch]$skipDetailedPhoneInfo = $false,

    [Parameter(Mandatory = $false)]
    [switch]$openBrowser = $false
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
$Skus = Invoke-MgGraphRequest -Uri "Beta/subscribedSkus" -OutputType PSObject | Select-Object -Expand Value
foreach ($item in $items) {
    $Search = $skus | Where-Object { $_.ServicePlans.servicePlanName -contains "$item" }
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
$organisationName = (Invoke-MgGraphRequest -Uri "v1.0/organization" -OutputType PSObject | Select-Object -Expand value).DisplayName

#Return an array of authentication methods including whether they are enabled or not and for which users
Function Get-AuthenticationMethods {
    $policies = Invoke-MgGraphRequest -Uri "beta/policies/authenticationmethodspolicy" -OutputType PSObject | Select-Object -Expand authenticationMethodConfigurations
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
    $userRegistrations = Invoke-MgGraphRequest -Uri "Beta/reports/authenticationMethods/userRegistrationDetails?`$top=$limit&`$orderby=userPrincipalName" -OutputType PSObject | Select-Object -Expand Value
    
    if ($skipGuest) {
        $userRegistrations = $userRegistrations | Where-Object { $_.userType -ne "guest" }
    }

    $usersWithMobileMethods = $userRegistrations | Where-Object { $_.methodsRegistered -contains "mobilePhone" } | Select-Object id, userPrincipalName, methodsRegistered
    
    Foreach ($user in $usersWithMobileMethods) {
        $methodsFromReport = $user.methodsRegistered
        $methodsToReplace = @()
        $methodsToReplace += $methodsFromReport | Where-Object { $_ -ne "mobilePhone" }
        $methodsToReplace += "Voice Call"  
        
        if (-not $skipDetailedPhoneInfo) {
            $Methods = Invoke-MgGraphRequest -uri "/beta/users/$($user.id)/authentication/methods" -OutputType PSObject | Where-Object { $_."@odata.type" -eq '#microsoft.graph.phoneAuthenticationMethod'}
            if ($Methods.smsSignInState -eq "ready") { 
                $methodsToReplace += "SMS" 
            }
        }
    
        $user.methodsRegistered = $methodsToReplace
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
        $EligiblePIMRoles = Invoke-MgGraphRequest -Uri "beta/roleManagement/directory/roleEligibilitySchedules?`$expand=*" -OutputType PSObject | Select-Object -Expand Value
        $AssignedPIMRoles = Invoke-MgGraphRequest -Uri "beta/roleManagement/directory/roleAssignmentSchedules?`$expand=*" -OutputType PSObject | Select-Object -Expand Value
        $DirectoryRoles = $EligiblePIMRoles + $AssignedPIMRoles
        $DirectoryRoleUsers = $DirectoryRoles | Where-Object { $_.Principal.'@odata.type' -eq "#microsoft.graph.user" }
        $RoleMembers = $DirectoryRoleUsers.Principal.userPrincipalName | Select-Object -Unique
    }
    else {
        #Get all members or directory roles
        $DirectoryRoles = Invoke-MgGraphRequest -Uri "/beta/directoryRoles?" -OutputType PSObject | Select-Object -Expand Value
        $RoleMembers = $DirectoryRoles | ForEach-Object { Invoke-MgGraphRequest -uri "/beta/directoryRoles/$($_.id)/members" -OutputType PSObject | Select-Object -Expand Value } | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.user" } | Select-Object -expand userPrincipalName -Unique
    }
    $PrivilegedUserRegistrationDetails = $userRegistrationsReport | Where-Object { $RoleMembers -contains $_.userPrincipalName }
    Return $PrivilegedUserRegistrationDetails
}

###Method types array
$AllMethods = @(
    [pscustomobject]@{type='microsoftAuthenticatorPasswordless';Name='Microsoft Authenticator Passwordless';Strength='Strong'}
    [pscustomobject]@{type='fido2SecurityKey';AltName='Fido2';Name='Fido2 Security Key';Strength='Strong'}
    [pscustomobject]@{type='passKeyDeviceBound';AltName='Fido2';Name='Device Bound Passkey';Strength='Strong'}
    [pscustomobject]@{type='passKeyDeviceBoundAuthenticator';AltName='Fido2';Name='Microsoft Authenticator Passkey';Strength='Strong'}
    [pscustomobject]@{type='passKeyDeviceBoundWindowsHello';AltName='Fido2';Name='Windows Hello Passkey';Strength='Strong'}
    [pscustomobject]@{type='microsoftAuthenticatorPush';AltName='MicrosoftAuthenticator';Name='Microsoft Authenticator App';Strength='Strong'}
    [pscustomobject]@{type='softwareOneTimePasscode';AltName='SoftwareOath';Name='Software OTP';Strength='Strong'}
    [pscustomobject]@{type='hardwareOneTimePasscode';AltName='HardwareOath';Name='Hardware OTP';Strength='Strong'}
    [pscustomobject]@{type='windowsHelloForBusiness';AltName='windowsHelloForBusiness';Name='Windows Hello for Business';Strength='Strong'}
    [pscustomobject]@{type='temporaryAccessPass';AltName='TemporaryAccessPass';Name='Temporary Access Pass';Strength='Strong'}
    [pscustomobject]@{type='macOsSecureEnclaveKey';Name='MacOS Secure Enclave Key';Strength='Strong'}
    [pscustomobject]@{type='SMS';AltName='SMS';Name='SMS';Strength='Weak'}
    [pscustomobject]@{type='Voice Call';AltName='voice';Name='Voice Call';Strength='Weak'}
    [pscustomobject]@{type='email';AltName='Email';Name='Email';Strength='Weak'}
    [pscustomobject]@{type='alternateMobilePhone';AltName='Voice';Name='Alternative Mobile Phone';Strength='Weak'}
    [pscustomobject]@{type='securityQuestion';AltName='Security Questions';Name='Security Questions';Strength='Weak'}
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
$disabledAuthenticationMethods = $authenticationMethods | Where-Object { $_.State -eq "Disabled" }
$enabledAuthenticationMethods = $authenticationMethods | Where-Object { $_.State -eq "Enabled" }
#Get methods enabled and disabled by policy
$MethodsDisabledByPolicy = $AllMethods | Where-Object { $_.AltName -in $disabledAuthenticationMethods.DisplayName }
$MethodsEnabledByPolicy = $AllMethods | Where-Object { $_.AltName -in $enabledAuthenticationMethods.DisplayName }
#get weak authentication methods and count
$enabledWeakAuthenticationMethods = $MethodsEnabledByPolicy | Where-Object { $_.Strength -eq "Weak" }

###Calculate totals
#Total number of users
$totalUsersCount = $userRegistrationsReport.Count

### Calculate MFA capable info
Write-output "Analyzing MFA info..."
$totalMFACapableUsers = $userRegistrationsReport | Where-Object { $_.isMfaCapable -eq $true }
$totalMFACapableUsersCount = $totalMFACapableUsers.Count
#Calculate percentage of MFA capable users
$MfaCapablePercentage = 0
if ($totalUsersCount -gt 0) {
    $MfaCapablePercentage = [math]::Round(($totalMFACapableUsersCount / $totalUsersCount) * 100, 2)
}

###Calculate passwordless info
Write-output "Analyzing passwordless info..."
$totalPasswordlessUsers = $userRegistrationsReport | Where-Object { $_.isPasswordlessCapable -eq $true }
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

### Calculate privileged users not using phish resistant methods
Write-output "Analyzing privileged users not using phish resistant methods..."
$PrivilegedUsersRegistrationDetails = Get-PrivilegedUserRegistrationDetails -userRegistrations $userRegistrationsReport
$PrivilegedUsersNotUsingPhishResistantMethods = $PrivilegedUsersRegistrationDetails | Where-Object { $_.methodsRegistered -notcontains "fido2SecurityKey" -and $_.methodsRegistered -notcontains "passKeyDeviceBound" -and $_.methodsRegistered -notcontains "passKeyDeviceBoundAuthenticator" }
# Count of privileged users not using phish resistant methods
$PrivilegedUsersNotUsingPhishResistantMethodsCount = $PrivilegedUsersNotUsingPhishResistantMethods.Count

function Minify-HTML {
    param([string]$html)
    
    $codeBlocks = @()
    $pattern = '(<pre.*?>.*?</pre>|<code.*?>.*?</code>)'
    $html = [regex]::Replace($html, $pattern, {
        param($match)
        $codeBlocks += $match.Value
        return "CODE_BLOCK_PLACEHOLDER_$($codeBlocks.Count - 1)"
    }, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    
    $html = $html -replace '<!--(?!\[if)(.*?)-->', ''
    
    $html = $html -replace '>\s+<', '><'
    $html = $html -replace '\s{2,}', ' '
    
    $html = $html -replace '\s+>', '>'
    $html = $html -replace '>\s+', '>'
    $html = $html -replace '\s+/>', '/>'
    
    for ($i = 0; $i -lt $codeBlocks.Count; $i++) {
        $html = $html -replace "CODE_BLOCK_PLACEHOLDER_$i", $codeBlocks[$i]
    }
    
    return $html.Trim()
}

## Generate HTML report
Write-output "Generating HTML report..."
Function Generate-EntraAuthReport {
    param(
        [Parameter(Mandatory = $true)]
        [array]$UserRegistrations,
        
        [Parameter(Mandatory = $true)]
        [array]$MethodTypes,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "C:\GitHub\Private\Reports\EntraAuthenticationReport.html"
    )

    # Define Auth methods headers
    $authMethodsHeaders = $MethodTypes | ForEach-Object {
        $cssClass = if ($_.Strength -eq "Strong") { "strong-method" } else { "weak-method" }
        $dataAttributes = ""

        # Check if this method is disabled by policy
        $isDisabled = $MethodsDisabledByPolicy.Name -contains $_.Name
        
        if ($isDisabled) {
            $dataAttributes = "data-disabled=`"true`""
        }
        
        return "<th class=`"$($cssClass) diagonal-header`" $($dataAttributes)><div>$($_.Name)</div></th>"
    } | Out-String

    # Process only relevant data
    $tableData = $UserRegistrations | ForEach-Object {
        $hasStrongMethods = $false
        $hasWeakMethods = $false
        $isPrivileged = $false
        $isSync = $false
        $isExternal = $false
        
        # Check if user has strong or weak methods
        foreach ($method in $_.methodsRegistered) {
            if ($strongMethodTypes -contains $method) {
                $hasStrongMethods = $true
            }
            if ($weakMethodTypes.type -contains $method) {
                $hasWeakMethods = $true
            }
        }

        # Check if user is privileged
        if ($PrivilegedUsersRegistrationDetails.userPrincipalName -contains $_.userPrincipalName) {
            $isPrivileged = $true
        }

        # Check if user is a sync user
        if (($_.userPrincipalName -like "Sync_*") -or ($_.userPrincipalName -like "ADToAADSyncServiceAccount*")) {
            $isSyncUser = $true
        }

        # Check if user is an external user
        if ($_.userPrincipalName -like "*#EXT#*") {
            $isExternal = $true
        }

        [PSCustomObject]@{
            userPrincipalName = $_.userPrincipalName
            methodsRegistered = $_.methodsRegistered
            defaultMfaMethod = $_.defaultMfaMethod
            hasStrongMethods = $hasStrongMethods
            hasWeakMethods = $hasWeakMethods
            isPasswordlessCapable = $_.isPasswordlessCapable
            isMfaCapable = $_.isMfaCapable
            isPrivileged = $isPrivileged
            isSync = $isSync
            isExternal = $isExternal
        }
    }
    
    # Convert to JSON
    $userRegistrationsJson = $tableData | ConvertTo-Json -Compress
    $methodTypesJson = $MethodTypes | ConvertTo-Json -Compress
    
    $backtick = [char]96

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

        #expand-button {
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
            margin-left: 0;
        }
        
        #expand-button:hover {
            background-color: #ddd;
        }
        
        #expand-button svg {
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
        .pagination-container {
            padding: 10px;
            display: flex;
            justify-content: flex-end;
            align-items: center;
            gap: 15px;
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
        
        #close-modal-button {
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
        
        #close-modal-button:hover {
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

        #export-csv-button {
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
        
        #export-csv-button:hover {
            background-color: #ddd;
        }
        
        #export-csv-button svg {
            width: 16px;
            height: 16px;
            margin-right: 5px;
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
                <div class="tenant">Org: $($organisationName)</div>
            </div>
        </div>
    </div>
    <div class="content-container">
        <!-- Add progress bar section -->
        <div class="progress-container" style="max-width: 100%; margin-bottom: 30px;">
            <div class="progress-title">Progress Towards Passwordless Authentication</div>
            <div class="progress-bar-container">
                <div class="progress-bar" style="width: $($passwordlessCapablePercentage)%"></div>
                <div class="progress-text">$($passwordlessCapablePercentage)% Complete</div>
            </div>
            <div class="progress-info">
                <span>0%</span>
                <span>Target: 100% of users passwordless capable</span>
                <span>100%</span>
            </div>
            <div class="progress-legend">
                <div class="legend-item" id="legend-item-passwordless-capable">
                    <div class="legend-color" style="background-color: #57A773;"></div>
                    <span>$($totalPasswordlessUsersCount) users passwordless capable</span>
                </div>
                <div class="legend-item" id="legend-item-not-passwordless-capable">
                    <div class="legend-color" style="background-color: #e0e0e0;"></div>
                    <span>$($totalUsersCount - $totalPasswordlessUsersCount) users still need passwordless capability</span>
                </div>
            </div>
        </div>

        <div class="summary-stats">
            <div class="stat-card" id="stat-card-total">
                <div class="stat-title">Total Users</div>
                <div class="stat-value">$($totalUsersCount)</div>
            </div>
            <div class="stat-card" id="stat-card-mfa-capable">
                <div class="stat-title">MFA Capable Users</div>
                <div class="stat-value">$($totalMFACapableUsersCount)</div>
                <div class="stat-percentage">$($MfaCapablePercentage)% of users</div>
            </div>
            <div class="stat-card" id="stat-card-strong-methods">
                <div class="stat-title">Strong Auth Methods</div>
                <div class="stat-value">$($totalStrongAuthUsersCount)</div>
                <div class="stat-percentage">$($strongAuthPercentage)% of users</div>
            </div>
            <div class="stat-card" id="stat-card-passwordless-capable">
                <div class="stat-title">Passwordless Capable</div>
                <div class="stat-value">$($totalPasswordlessUsersCount)</div>
                <div class="stat-percentage">$($passwordlessCapablePercentage)% of users</div>
            </div>
            <div class="stat-card" id="stat-card-mixed-methods">
                <div class="stat-title">Strong + Weak Auth</div>
                <div class="stat-value">$($totalBothMethodTypesCount)</div>
                <div class="stat-percentage">$($bothMethodsPercentage)% of users</div>
            </div>
        </div>

        <div class="search-container">
            <input type="text" id="searchBox" placeholder="Search for a user...">
        </div>
        
        <div class="switches-group">
            <div class="switch-container">
                <label class="switch">
                    <input type="checkbox" id="hideDisabledSwitch">
                    <span class="slider"></span>
                </label>
                <span class="switch-label">Hide Disabled Authentication Methods</span>
            </div>
            
            <div class="switch-container">
                <label class="switch">
                    <input type="checkbox" class="filter-switch" id="hideMfaCapableSwitch">
                    <span class="slider"></span>
                </label>
                <span class="switch-label">Hide MFA Capable Users</span>
            </div>
            
            <div class="switch-container">
                <label class="switch">
                    <input type="checkbox" class="filter-switch" id="hideExternalUsersSwitch">
                    <span class="slider"></span>
                </label>
                <span class="switch-label">Hide External Users</span>
            </div>
            
            <div class="switch-container">
                <label class="switch">
                    <input type="checkbox" class="filter-switch" id="hideSyncUsersSwitch">
                    <span class="slider"></span>
                </label>
                <span class="switch-label">Hide Sync_ Account</span>
            </div>
        </div>
        
        <div class="filter-container">
            <button class="filter-button active" data-filter="all">All Users</button>
            <button class="filter-button" data-filter="privileged">Privileged Users</button>
            <button class="filter-button" data-filter="passwordless">Passwordless Capable</button>
            <button class="filter-button" data-filter="non-passwordless">Non-Passwordless Capable</button>
            <button class="filter-button" data-filter="strong">Strong Methods</button>
            <button class="filter-button" data-filter="mixed">Strong+Weak Methods</button>
            <button class="filter-button" data-filter="weak">Weak Methods Only</button>
            <div class="button-group">
                <button id="export-csv-button" title="Export table to CSV file">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"></path>
                        <polyline points="7 10 12 15 17 10"></polyline>
                        <line x1="12" y1="15" x2="12" y2="3"></line>
                    </svg>
                    Export CSV
                </button>
                <button id="expand-button" title="Expand table to full screen">
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
                        $($authMethodsHeaders)
                    </tr>
                </thead>
                <tbody id="virtual-tbody"></tbody>
            </table>
        </div>
        
        <!-- Modal for fullscreen table -->
        <div id="tableModal" class="modal">
            <div class="modal-content">
                <span id="close-modal-button">&times;</span>
                <h2>Authentication Methods - Expanded View</h2>
                <div class="fullscreen-table-container">
                    <!-- The table will be cloned here via JavaScript -->
                </div>
            </div>
        </div>

        <div class="footer">
            <p>Authentication Methods report generated via Microsoft Graph API | $($organisationName)</p>
        </div>
    </div>

    <script>
        const usersData = $($userRegistrationsJson);
        const authMethods = $($methodTypesJson);

        const totalUsers = $($totalUsersCount);
        const mfaCapableUsers = $($totalMFACapableUsersCount);
        const strongAuthUsers = $($totalStrongAuthUsersCount);
        const passwordlessUsers = $($totalPasswordlessUsersCount);
        const mixedAuthUsers = $($totalBothMethodTypesCount);
        
        /* Store external user counts for recalculation */
        const externalUserCounts = {
            total: 0,
            mfaCapable: 0,
            strongAuth: 0,
            passwordless: 0,
            mixedAuth: 0
        };
        
        /* Store sync user counts for recalculation */
        const syncUserCounts = {
            total: 0,
            mfaCapable: 0,
            strongAuth: 0,
            passwordless: 0,
            mixedAuth: 0
        };

        /* Calculate external and sync users counters */
        for (let i = 0; i < usersData.length; i++) {
            if (usersData[i].isExternal) {
                externalUserCounts.total++;
                if(usersData[i].isMfaCapable) externalUserCounts.mfaCapable++;
                if(usersData[i].hasStrongMethods) externalUserCounts.strongAuth++;
                if(usersData[i].isPasswordlessCapable) externalUserCounts.passwordless++;
                if(usersData[i].hasStrongMethods && usersData[i].hasWeakMethods) externalUserCounts.mixedAuth++;
            }

            if (usersData[i].isSync) {
                syncUserCounts.total++;
                if(usersData[i].isMfaCapable) syncUserCounts.mfaCapable++;
                if(usersData[i].hasStrongMethods) syncUserCounts.strongAuth++;
                if(usersData[i].isPasswordlessCapable) syncUserCounts.passwordless++;
                if(usersData[i].hasStrongMethods && usersData[i].hasWeakMethods) syncUserCounts.mixedAuth++;
            }
        }

        class VirtualTable {
            constructor(options) {
                this.container = options.container;
                this.paginationContainers = [
                    document.createElement('div'),
                    document.createElement('div'),
                ];
                this.container.prepend(this.paginationContainers[0]);
                this.container.append(this.paginationContainers[1]);
                this.data = options.data || [];
                this.tbody = options.tbody;
                this.renderFunction = options.renderRow || this.defaultRenderRow;
                
                this.rowsPerPage = 100;
                this.currentPage = 1;

                this.render();
                this.renderPagination();
            }

            render() {
                const startIndex = (this.currentPage - 1) * this.rowsPerPage;
                const endIndex = startIndex + this.rowsPerPage;

                this.tbody.innerHTML = '';

                for (let i = Math.max(0, startIndex); i < Math.min(this.data.length, endIndex); i++) {
                    const row = this.renderFunction(this.data[i], i);
                    this.tbody.appendChild(row);
                }
            }

            renderPagination() {
                this.paginationContainers.forEach(c => {
                    c.innerHTML = '';
                    c.className = 'pagination-container';
                
                    const pageSelector = document.createElement('input');
                    pageSelector.className = 'page-selector-input';
                    pageSelector.setAttribute('type', 'number');
                    pageSelector.setAttribute('min', 1);
                    pageSelector.setAttribute('max', this.getPageCount());
                    pageSelector.value = this.currentPage;
                    pageSelector.addEventListener('input', e => this.updatePage(e.target.value));
                    
                    const pageSelectorDiv = document.createElement('div');
                    pageSelectorDiv.appendChild(pageSelector);

                    const pageLabel = document.createElement('div');
                    pageLabel.textContent = 'Page';

                    const totalLabel = document.createElement('div');
                    totalLabel.textContent = 'of ' + this.getPageCount();

                    c.appendChild(pageLabel);
                    c.appendChild(pageSelectorDiv);
                    c.appendChild(totalLabel);
                });
            }

            defaultRenderRow(rowData, index) {
                const tr = document.createElement('tr');
                tr.dataset.index = index;

                /* Create cells based on rowData properties */
                Object.values(rowData).forEach(value => {
                    const td = document.createElement('td');
                    td.textContent = value;
                    tr.appendChild(td);
                });

                return tr;
            }

            updateData(newData) {
                this.data = newData;
                this.currentPage = 1;
                this.render();
                this.renderPagination();
            }

            updatePage(newPage) {
                if (newPage <= 0) return;
                if (newPage > this.getPageCount()) return;

                document.querySelectorAll('.page-selector-input').forEach(el => {
                    el.value = newPage;
                });

                this.currentPage = newPage;
                this.render();
            }

            getPageCount() {
                return Math.ceil((this.data.length - 1) / this.rowsPerPage); 
            }
        };

        /* After page loads, initialize virtual table */
        document.addEventListener('DOMContentLoaded', function() {
            const hiddenColumnIndices = [];
            const virtualTable = new VirtualTable({
                container: document.querySelector('.table-container'),
                tbody: document.getElementById('virtual-tbody'),
                data: usersData,
                renderRow: (rowData, index) => {
                    const tr = document.createElement('tr');
                    const trCols = [];

                    trCols.push($($backtick)<td title=`"`${rowData.userPrincipalName}`">`${rowData.userPrincipalName}</td>$($backtick));
                    trCols.push($($backtick)<td title=`"`${rowData.defaultMfaMethod}`">`${rowData.defaultMfaMethod}</td>$($backtick));
                    trCols.push($($backtick)<td>`${rowData.isMfaCapable ? "<span class='checkmark'>✓</span>" : "<span class='x-mark'>✗</span>"}</td>$($backtick));
                    trCols.push($($backtick)<td>`${rowData.isPasswordlessCapable ? "<span class='checkmark'>✓</span>" : "<span class='x-mark'>✗</span>" }</td>$($backtick));

                    authMethods.forEach(m => {
                        trCols.push($($backtick)<td>`${ rowData.methodsRegistered.includes(m) ? "<span class='checkmark'>✓</span>" : "<span class='x-mark'>✗</span>" }</td>$($backtick));
                    });

                    tr.innerHTML = trCols.filter((c, i) => !hiddenColumnIndices.includes(i)).join('');
                    return tr;
                }
            });

            /* Handle export table data to CSV button */
            document.getElementById('export-csv-button').addEventListener('click', function() {
                /* Create a simple CSV string with proper formatting */
                const csvContent = [];

                /* Get the table and header cells */
                const table = document.getElementById('authMethodsTable');
                const headerRow = table.querySelector('thead tr');
                const headerCells = headerRow.querySelectorAll('th');

                /* Create header row for CSV */
                const headerCsvRow = [];
                for (let i = 0; i < headerCells.length; i++) {
                    if (headerCells[i].style.display !== 'none') {
                        const cellText = headerCells[i].textContent.trim();
                        headerCsvRow.push(sanitizeCsvString(cellText));
                    }
                }

                /* define extra columns to apply filters in the spreadsheet */ 
                headerCsvRow.push('MFA capable');
                headerCsvRow.push('External user');
                headerCsvRow.push('Sync user');
                headerCsvRow.push('Strong methods');
                headerCsvRow.push('Only weak methods');
                headerCsvRow.push('Mixed methods');
                headerCsvRow.push('Privileged');

                csvContent.push(headerCsvRow.join(','));

                for (let i = 0; i < virtualTable.data.length; i++) {
                    const csvRow = [];
                    const rowData = virtualTable.data[i];

                    csvRow.push(sanitizeCsvString(rowData.userPrincipalName));
                    csvRow.push(sanitizeCsvString(rowData.defaultMfaMethod));
                    csvRow.push(rowData.isMfaCapable ? 'Yes' : 'No');
                    csvRow.push(rowData.isPasswordlessCapable ? 'Yes' : 'No');
                    authMethods.forEach(m => {
                        csvRow.push(rowData.methodsRegistered.includes(m) ? 'Yes' : 'No');
                    });

                    /* fill the extra columns */ 
                    csvRow.push(rowData.isMfaCapable ? 'Yes' : 'No');
                    csvRow.push(rowData.isExternal ? 'Yes' : 'No');
                    csvRow.push(rowData.isSync ? 'Yes' : 'No');
                    csvRow.push(rowData.hasStrongMethods ? 'Yes' : 'No');
                    csvRow.push(rowData.hasWeakMethods && !rowData.hasStrongMethods ? 'Yes' : 'No');
                    csvRow.push(rowData.hasWeakMethods && rowData.hasStrongMethods ? 'Yes' : 'No');
                    csvRow.push(rowData.isPrivileged ? 'Yes' : 'No');

                    csvContent.push(csvRow.filter((c, i) => !hiddenColumnIndices.includes(i)).join(','));
                }

                /* Join all rows with proper newlines */
                const csvString = csvContent.join('\r\n');

                /* Get date for filename */
                const today = new Date();
                /* YYYY-MM-DD format */
                const date = today.toISOString().split('T')[0];

                /* Create download link with data URI */
                const downloadLink = document.createElement('a');

                /* Add BOM for proper UTF-8 encoding in Excel */
                const BOM = '\uFEFF';
                const encodedUri = 'data:text/csv;charset=utf-8,' + encodeURIComponent(BOM + csvString);

                downloadLink.setAttribute('href', encodedUri);
                downloadLink.setAttribute('download', 'Entra_Auth_Methods_Report_' + date + '.csv');
                document.body.appendChild(downloadLink);

                /* Trigger download and remove link */
                downloadLink.click();
                document.body.removeChild(downloadLink);
            });

            /* Handle expand fullscreen button */
            document.getElementById('expand-button').addEventListener('click', function() {
                const modal = document.getElementById('tableModal');
                const originalTable = document.getElementById('authMethodsTable');
                const fullscreenContainer = document.querySelector('.fullscreen-table-container');

                /* Clone the table for the modal */
                const clonedTable = originalTable.cloneNode(true);
                clonedTable.id = 'fullscreenTable';

                /* Clear previous content and add the cloned table */
                fullscreenContainer.innerHTML = '';
                fullscreenContainer.appendChild(clonedTable);

                /* Show the modal */
                modal.style.display = 'block';
                document.body.classList.add('modal-open');
            });

            /* Handle close fullscreen modal */
            document.getElementById('close-modal-button').addEventListener('click', function() {
                const modal = document.getElementById('tableModal');
                modal.style.display = 'none';
                document.body.classList.remove('modal-open');
            });

            /* Handle search filter */
            document.getElementById('searchBox').addEventListener('keyup', () => filterTable());

            /* Handle disabled auth methods switch */
            document.getElementById('hideDisabledSwitch').addEventListener('change', function() {
                const isHiding = this.checked;

                /* Get all table headers and find disabled ones */
                const table = document.getElementById('authMethodsTable');
                const headers = table.getElementsByTagName('th');

                hiddenColumnIndices.length = 0;

                /* Loop through all headers to find disabled methods */
                for (let i = 0; i < headers.length; i++) {
                    if (headers[i].hasAttribute('data-disabled')) {
                        headers[i].style.display = '';
                        /* Hide/show the header */
                        if (isHiding) {
                            headers[i].style.display = 'none';
                            hiddenColumnIndices.push(i);
                        }
                    }
                }

                virtualTable.render();
            });

            /* Handle switch filters */
            document.querySelectorAll('.filter-switch').forEach(el => {
                el.addEventListener('change', () => filterTable());
            });

            /* Handle button filters */
            document.querySelectorAll('.filter-button').forEach(el => {
                el.addEventListener('click', function() {
                    const buttons = document.querySelectorAll('.filter-button');
                    buttons.forEach(btn => btn.classList.remove('active'));
                    this.classList.add('active');
                    filterTable();
                });
            });

            function filterTable() {
                const searchTerm = document.getElementById('searchBox').value.toUpperCase() ?? '';
                const isHidingMfaCapableUsers = document.getElementById('hideMfaCapableSwitch').checked;
                const isHidingExternalUsers = document.getElementById('hideExternalUsersSwitch').checked;
                const isHidingSyncUsers = document.getElementById('hideSyncUsersSwitch').checked;
                const buttonFilterValue = document.querySelector('.filter-button.active').getAttribute('data-filter');

                const filteredData = usersData.filter(r => {
                    if (searchTerm !== '' && r.userPrincipalName.toUpperCase().indexOf(searchTerm) === -1) {
                        return false;
                    }

                    if (isHidingMfaCapableUsers && r.isMfaCapable) {
                        return false;
                    }

                    if (isHidingExternalUsers && r.isExternal) {
                        return false;
                    }

                    if (isHidingSyncUsers && r.isSync) {
                        return false;
                    }

                    switch (buttonFilterValue) {
                        case 'strong':
                            if (!r.hasStrongMethods) return false;
                            break;
                        case 'weak':
                            if (!r.hasWeakMethods || r.hasStrongMethods) return false;
                            break;
                        case 'passwordless':
                            if (!r.isPasswordlessCapable) return false;
                            break;
                        case 'non-passwordless':
                            if (r.isPasswordlessCapable) return false;
                            break;
                        case 'mixed':
                            if (!r.hasWeakMethods || !r.hasStrongMethods) return false;
                            break;
                        case 'privileged':
                            if (!r.isPrivileged) return false;
                            break;
                    }

                    return true;
                });

                virtualTable.updateData(filteredData);
                updateSummaryStats(isHidingExternalUsers, isHidingSyncUsers);
            }

            /* Update all summary cards and progress bar */
            function updateSummaryStats(hideExternal, hideSync) {
                /* Calculate adjusted counts */
                let adjustedTotal = totalUsers;
                let adjustedMfa = mfaCapableUsers;
                let adjustedStrong = strongAuthUsers;
                let adjustedPasswordless = passwordlessUsers;
                let adjustedMixed = mixedAuthUsers;

                /* Subtract external users if they're hidden */
                if (hideExternal) {
                    adjustedTotal -= externalUserCounts.total;
                    adjustedMfa -= externalUserCounts.mfaCapable;
                    adjustedStrong -= externalUserCounts.strongAuth;
                    adjustedPasswordless -= externalUserCounts.passwordless;
                    adjustedMixed -= externalUserCounts.mixedAuth;
                }

                /* Subtract sync users if they're hidden */
                if (hideSync) {
                    adjustedTotal -= syncUserCounts.total;
                    adjustedMfa -= syncUserCounts.mfaCapable;
                    adjustedStrong -= syncUserCounts.strongAuth;
                    adjustedPasswordless -= syncUserCounts.passwordless;
                    adjustedMixed -= syncUserCounts.mixedAuth;
                }

                /* Calculate percentages */
                const mfaPercentage = adjustedTotal > 0 ? Math.round((adjustedMfa / adjustedTotal) * 100 * 100) / 100 : 0;
                const strongPercentage = adjustedTotal > 0 ? Math.round((adjustedStrong / adjustedTotal) * 100 * 100) / 100 : 0;
                const passwordlessPercentage = adjustedTotal > 0 ? Math.round((adjustedPasswordless / adjustedTotal) * 100 * 100) / 100 : 0;
                const mixedPercentage = adjustedTotal > 0 ? Math.round((adjustedMixed / adjustedTotal) * 100 * 100) / 100 : 0;

                /* Update summary cards */
                document.querySelector('#stat-card-total .stat-value').textContent = adjustedTotal;

                document.querySelector('#stat-card-mfa-capable .stat-value').textContent = adjustedMfa;
                document.querySelector('#stat-card-mfa-capable .stat-percentage').textContent = mfaPercentage + '% of users';

                document.querySelector('#stat-card-strong-methods .stat-value').textContent = adjustedStrong;
                document.querySelector('#stat-card-strong-methods .stat-percentage').textContent = strongPercentage + '% of users';

                document.querySelector('#stat-card-passwordless-capable .stat-value').textContent = adjustedPasswordless;
                document.querySelector('#stat-card-passwordless-capable .stat-percentage').textContent = passwordlessPercentage + '% of users';

                document.querySelector('#stat-card-mixed-methods .stat-value').textContent = adjustedMixed;
                document.querySelector('#stat-card-mixed-methods .stat-percentage').textContent = mixedPercentage + '% of users';

                /* Update progress bar */
                const progressBar = document.querySelector('.progress-bar');
                const progressText = document.querySelector('.progress-text');
                const passwordlessLegend = document.querySelector('#legend-item-passwordless-capable span');
                const nonPasswordlessLegend = document.querySelector('#legend-item-not-passwordless-capable span');

                progressBar.style.width = passwordlessPercentage + '%';
                progressText.textContent = passwordlessPercentage + '% Complete';
                passwordlessLegend.textContent = adjustedPasswordless + ' users passwordless capable';
                nonPasswordlessLegend.textContent = (adjustedTotal - adjustedPasswordless) + ' users still need passwordless capability';
            }
        });

        function sanitizeCsvString(value) {
            return '"' + value.replace(/"/g, '""') + '"';
        }
    </script>
</body>
</html>
"@)

    # Generate the path
    $OutputPath = Join-Path -Path $outpath -ChildPath "Entra_Authentication_Methods_Report.html"

    # Output HTML report
    $minifiedHtml = Minify-HTML -html $html.ToString()
    $minifiedHtml | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-output "HTML report generated at $OutputPath"
    
    # Open the report in the default browser
    if ($openBrowser) {
        Start-Process $OutputPath
    }
}

# Generate the report
Generate-EntraAuthReport -UserRegistrations $userRegistrationsReport -MethodTypes $AllMethods -OutputPath $OutputPath