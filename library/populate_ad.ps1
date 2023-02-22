#!powershell

# Copyright: (c) 2023 Helvio Junior (M4v3r1ck), Inc. All Rights Reserved.
# SPDX-License-Identifier: GPL-3.0-only
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#Requires -Module ActiveDirectory

# Based on
#https://github.com/ansible-collections/community.windows/blob/main/plugins/modules/win_domain_ou.ps1
#https://github.com/ansible-collections/community.windows/blob/main/plugins/modules/win_domain_group.ps1
#https://github.com/ansible-collections/community.windows/blob/main/plugins/modules/win_domain_user.ps1


#AnsibleRequires -CSharpUtil Ansible.Basic
Set-StrictMode -Version 2.0

$spec = @{
    options = @{
        ous = @{ type = "list"; required = $true }
        groups = @{ type = "list"; required = $true }
        users = @{ type = "list"; required = $true }
        domain_username = @{ type = "str"; }
        domain_password = @{ type = "str"; no_log = $true }
        domain_server = @{ type = "str" }
    }
    required_together = @(
        , @('domain_password', 'domain_username')
    )
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$extra_args = @{}
$onboard_extra_args = @{}
if ($null -ne $module.Params.domain_username) {
    $domain_password = ConvertTo-SecureString $module.Params.domain_password -AsPlainText -Force
    $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $module.Params.domain_username, $domain_password
    $extra_args.Credential = $credential
    $onboard_extra_args.Credential = $credential
}
if ($null -ne $module.Params.domain_server) {
    $extra_args.Server = $module.Params.domain_server
    $onboard_extra_args.Server = $module.Params.domain_server
}

$extra_args.Properties = '*'
$extra_args.Filter = '*'
$Properties = '*'
$groups_missing_behaviour = "warn"

$check_mode = $module.CheckMode
$ous = $module.Params.ous
$groups = $module.Params.ous
$users = $module.Params.users
$protected = $false
$module.Diff.before = ""
$module.Diff.after = ""
$module.Result.ous = @()
$module.Result.groups = @()
$module.Result.users = @()
$module.Result.changed = $false

Function Get-SimulatedOu {
    Param($Object)
    $ou = @{
        Name = $Object.name
        DistinguishedName = "OU=$($Object.name),$($Object.path)"
        ProtectedFromAccidentalDeletion = $Object.protected
        Properties = New-Object Collections.Generic.List[string]
    }
    $ou.Properties.Add("Name")
    $ou.Properties.Add("DistinguishedName")
    $ou.Properties.Add("ProtectedFromAccidentalDeletion")
    if ($Object.Params.properties.Count -ne 0) {
        $Object.Params.properties.Keys | ForEach-Object {
            $property = $_
            $module.Result.simulate_property = $property
            $ou.Add($property, $Object.Params.properties.Item($property))
            $ou.Properties.Add($property)
        }
    }
    # convert to psobject & return
    [PSCustomObject]$ou
}

Function Get-OuObject {
    Param([PSObject]$Object)
    $obj = $Object | Select-Object -Property * -ExcludeProperty nTSecurityDescriptor | ConvertTo-Json -Depth 1 | ConvertFrom-Json
    return $obj
}

Function Get-PrincipalGroup {
    Param ($identity, $args_extra)
    try {
        $groups = Get-ADPrincipalGroupMembership `
            -Identity $identity `
            -ErrorAction Stop
    }
    catch {
        $module.Warn("Failed to enumerate user groups but continuing on: $($_.Exception.Message)")
        return @()
    }

    $result_groups = foreach ($group in $groups) {
        $group.DistinguishedName
    }
    return $result_groups
}

# attempt import of module
Try { Import-Module ActiveDirectory }
Catch { $module.FailJson("The ActiveDirectory module failed to load properly: $($_.Exception.Message)", $_) }
Try {
    $all_ous = Get-ADOrganizationalUnit @extra_args
}
Catch { $module.FailJson("Get-ADOrganizationalUnit failed: $($_.Exception.Message)", $_) }

if ($ous.count -ne 0) {
    $ous | ForEach-Object {
        $name = $_.name
        $path = $_.path

        # determine if requested OU exist
        $current_ou = $false
        Try {
            $current_ou = $all_ous | Where-Object {
                $_.DistinguishedName -eq "OU=$name,$path" }
            $module.Result.ous += @( Get-OuObject -Object $current_ou )
        }
        Catch {
            $current_ou = $false

        }

        # ou does not exist, create object
        if (-not $current_ou) {
            $params = @{}
            $params.Name = $name
            $params.Path = $path
            $params.ProtectedFromAccidentalDeletion = $protected
            Try {
                New-ADOrganizationalUnit @params @onboard_extra_args -WhatIf:$check_mode
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException] {
                #ignore
            }
            Catch {
                $module.FailJson("Failed to create organizational unit: $($_.Exception.Message)", $_)
            }
            $module.Result.created = $true
            if (-not $check_mode) {
                $new_ou = Get-ADOrganizationalUnit @extra_args | Where-Object {
                    $_.DistinguishedName -eq "OU=$name,$path"
                }
                #$module.Result.ous += @( $new_ou )
                $module.Warn("OU created: $($name)")
            }
        }


    }
}

if ($groups.count -ne 0) {
    $groups | ForEach-Object {
        $name = $_.name
        $path = $_.path

        try {
            $group = Get-ADGroup -Identity $name -Properties *
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            $group = $null
        }
        catch {
            $module.FailJson("failed to retrieve initial details for group $($name): $($_.Exception.Message)")
        }

        # If the group does not exist, create it
        If (-not $group) {
            $add_args = @{}
            $add_args.Name = $name
            $add_args.GroupScope = "global"

            # validate that path is an actual path
            if ($null -ne $path) {
                try {
                    Get-ADObject -Identity $path -Properties * | Out-Null
                }
                catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                    $module.FailJson("the group path $path for group $name does not exist, please specify a valid LDAP path")
                }
                $add_args.Path = $path
            }


            try {
                $group = New-AdGroup -WhatIf:$check_mode -PassThru @add_args
                #$module.Result.groups += @( $group )
            }
            catch {
                if (-not ($($_.Exception.Message).ToLower() -Contains 'already in use')) {
                    #$module.FailJson("failed to create group $($name): $($_.Exception.Message)", $($_.Exception))
                }
            }
            $module.Result.created = $true
            $module.Warn("Group created: $($name)")
        }



    }
}

if ($users.count -ne 0) {
    $users | ForEach-Object {
        $name = $_.name
        $path = $_.path
        $password = $_.passwd
        $memberof = $_.member_of

        try {
            $spn = $_.spn
        }
        catch {
            $spn = $null
        }

        try {
            $user_obj = Get-ADUser `
                -Identity $name `
                -Properties ('*', 'msDS-PrincipalName')
            $user_guid = $user_obj.ObjectGUID
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            $user_obj = $null
            $user_guid = $null
        }
        catch {
            $module.FailJson("failed to retrieve initial details for user $($name): $($_.Exception.Message)")
        }

        # If the account does not exist, create it
        If (-not $user_obj) {
            $create_args = @{}
            $create_args.Name = $name
            If ($null -ne $path) {
                $create_args.Path = $path
            }

            if ($null -ne $password) {
                $create_args.AccountPassword = ConvertTo-SecureString $password -AsPlainText -Force
            }
            $user_obj = New-ADUser @create_args -WhatIf:$check_mode -PassThru
            $user_guid = $user_obj.ObjectGUID
            $module.Result.created = $true
            $module.Result.changed = $true
            If ($check_mode) {
                $module.ExitJson()
            }
            $user_obj = Get-ADUser -Identity $user_guid -Properties ('*', 'msDS-PrincipalName')
            $module.Warn("User created: $($name)")
        }

        # Configure group assignment
        if ($null -ne $memberof) {
            $group_list = [Array]$memberof

            $groups = @(
                Foreach ($group in $group_list) {
                    try {
                        (Get-ADGroup -Identity $group -Properties *).DistinguishedName
                    }
                    catch {
                        if ($groups_missing_behaviour -eq "fail") {
                            $module.FailJson("Failed to locate group $($group): $($_.Exception.Message)", $_)
                        }
                        elseif ($groups_missing_behaviour -eq "warn") {
                            $module.Warn("Failed to locate group $($group) but continuing on: $($_.Exception.Message)")
                        }
                    }
                }
            )

            $assigned_groups = Get-PrincipalGroup $user_guid $extra_args

            Foreach ($group in $groups) {
                If (-not ($assigned_groups -Contains $group)) {
                    Add-ADGroupMember -Identity $group -Members $user_guid -WhatIf:$check_mode
                    $user_obj = Get-ADUser -Identity $user_guid -Properties *
                    $module.Result.changed = $true
                }
            }

        }

        # configure service principal names
        if ($null -ne $spn) {
            $current_spn = [Array]$user_obj.ServicePrincipalNames
            $desired_spn = [Array]$spn
            $spn_diff = @()

            # generate a diff
            $desired_spn | ForEach-Object {
                if ($current_spn -contains $_) {
                    $spn_diff += $_
                }
            }

            # the current spn list does not have any spn's in the desired list
            if (-not $spn_diff) {
                Set-ADUser `
                    -Identity $user_guid `
                    -ServicePrincipalNames @{ Add = $(($spn | ForEach-Object { "$($_)" } )) } `
                    -WhatIf:$check_mode
                $module.Result.changed = $true
            }
        }
    }
}

$module.ExitJson()
