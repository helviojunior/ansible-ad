#!powershell

# Copyright: (c) 2023 Helvio Junior (M4v3r1ck), Inc. All Rights Reserved.
# SPDX-License-Identifier: GPL-3.0-only
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#Requires -Module ActiveDirectory
#Requires -Module Ansible.ModuleUtils.Legacy

# Based on
#https://github.com/ansible-collections/community.windows/blob/main/plugins/modules/win_domain_ou.ps1
#https://github.com/ansible-collections/community.windows/blob/main/plugins/modules/win_domain_group.ps1
#https://github.com/ansible-collections/community.windows/blob/main/plugins/modules/win_domain_user.ps1

Set-StrictMode -Version 2.0

$spec = @{
    options = @{
        ous = @{ type = "list"; required = $false }
        groups = @{ type = "list"; required = $false }
        users = @{ type = "list"; required = $false }
        domain_username = @{ type = "str"; }
        domain_password = @{ type = "str"; no_log = $true }
        domain_server = @{ type = "str" }
    }
    required_together = @(
        , @('domain_password', 'domain_username')
    )
    required_one_of = @(
        , @('ous', 'groups', 'users')
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
$groups = $module.Params.groups
$users = $module.Params.users
$protected = $false
$module.Diff.before = ""
$module.Diff.after = ""

#https://docs.ansible.com/ansible/latest/reference_appendices/common_return_values.html#results
$module.Result.results = @()

#$module.Result.ous = @()
#$module.Result.groups = @()
#$module.Result.users = @()
#$module.Result.changed = $false

if (($null -eq $ous) -and ($null -eq $groups) -and ($null -eq $users)){
  $module.FailJson("You must inform at least one of this parameters (ous, groups, users)")
}

Function Merge-Dict {
  Param ([PSObject]$dict1, [PSObject]$dict2)
  $merged = $dict1 | ForEach-Object -Begin {[Hashtable]$aa = @{}} -Process {foreach($element in ($_.GetEnumerator())) {if (-not ($aa.ContainsKey($element.Key))) {
    try {
        $aa.Add($element.Key,[string]$element.Value)
    }
    catch {
        #nada
    }
    }}} -End {$aa}

  if ($null -ne $dict2) {
      $merged = $dict2 | ForEach-Object -Begin {[Hashtable]$aa = $merged} -Process {foreach($element in ($_.GetEnumerator())) {if (-not ($aa.ContainsKey($element.Key))) {
        try {
            $aa.Add($element.Key,[string]$element.Value)
        }
        catch {
            #nada
        }
        }}} -End {$aa}
  }
  return [Hashtable](@{} + $merged)
}

Function Get-ObjectData {
  Param ([PSObject]$object)
  $filtered = @{}
  if ($null -ne $object) {
      $filtered = ($Object | Select-Object -Property ObjectClass,ObjectCategory,DistinguishedName,DisplayName,CanonicalName,CN | ConvertTo-Json -Depth 1 | ConvertFrom-Json).psobject.properties | ForEach-Object -Begin {[Hashtable]$aa = @{}} -Process {foreach($element in ($_)) {if (-not ($aa.ContainsKey($element.Name))) {
        try {
            $aa.Add($element.Name,[string]$element.Value)
        }
        catch {
            #nada
        }
        }}} -End {$aa}
  }
  return [Hashtable]($filtered)
}

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

if (($null -ne $ous) -and ($ous.count -ne 0)) {
    $ous | ForEach-Object {
        $name = $_.name
        $path = $_.path
        $result_obj = @{}
        $result_obj.failed = $false
        $result_obj.changed = $false
        $result_obj.state = "present"
        $result_obj.name = $name
        $result_obj.ansible_loop_var = "item"
        $result_obj.item = "OU $name"


        # determine if requested OU exist
        $current_ou = $false
        Try {
            $current_ou = $all_ous | Where-Object {
                $_.DistinguishedName -eq "OU=$name,$path" }

            if ($null -ne $current_ou){
                $result_obj.changed = $true
                $result_obj = Merge-Dict $result_obj, (Get-ObjectData -Object $current_ou)
            }
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
            Catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException] {
                #ignore
            }
            Catch {
                if ($_.Exception.Message -inotmatch "already in use") {
                    $module.FailJson("Failed to create organizational unit: $($_.Exception.Message)", $_)
                }
            }
            $result_obj.created = $true
            if (-not $check_mode) {
                $new_ou = Get-ADOrganizationalUnit @extra_args | Where-Object {
                    $_.DistinguishedName -eq "OU=$name,$path"
                }
                #$module.Result.ous += @( $new_ou )
                $result_obj.msg = "OU created: $($name)"
                $result_obj = Merge-Dict $result_obj, (Get-ObjectData -Object $new_ou)
            }
        }

        $module.Result.results += @( $result_obj )

    }
}

if (($null -ne $groups) -and ($groups.count -ne 0)) {
    $groups | ForEach-Object {
        $name = $_.name
        $path = $_.path
        $result_obj = @{}
        $result_obj.failed = $false
        $result_obj.changed = $false
        $result_obj.state = "present"
        $result_obj.name = $name
        $result_obj.ansible_loop_var = "item"
        $result_obj.item = "Group $name"

        try {
            $group = Get-ADGroup -Identity $name -Properties *
            if ($null -ne $group){
                $result_obj.changed = $true
                $result_obj = Merge-Dict $result_obj, (Get-ObjectData -Object $group)
            }
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
                $result_obj.created = $true
                $result_obj = Merge-Dict $result_obj, (Get-ObjectData -Object $group)
            }
            catch {
                if (-not ($($_.Exception.Message).ToLower() -Contains 'already in use')) {
                    #$module.FailJson("failed to create group $($name): $($_.Exception.Message)", $($_.Exception))
                }
            }

        }

        $module.Result.results += @( $result_obj )

    }
}

if (($null -ne $users) -and ($users.count -ne 0)) {
    $users | ForEach-Object {
        $name = $_.name
        $password = $_.passwd
        $result_obj = @{}
        $result_obj.failed = $false
        $result_obj.changed = $false
        $result_obj.state = "present"
        $result_obj.name = $name
        $result_obj.ansible_loop_var = "item"
        $result_obj.item = "User $name"

        try {
            $path = $_.path
        }
        catch {
            $path = $null
        }

        try {
            $memberof = $_.member_of
        }
        catch {
            $memberof = @()
        }

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
            if ($null -ne $user_obj){
                $result_obj.changed = $true
                $result_obj = Merge-Dict $result_obj, (Get-ObjectData -Object $user_obj)
            }
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
            $create_args.Enabled = $true
            $create_args.PasswordNeverExpires = $true
            $create_args.ChangePasswordAtLogon = $false
            $create_args.SamAccountName = $name
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
            $result_obj.created = $true
            $result_obj = Merge-Dict $result_obj, (Get-ObjectData -Object $user_obj)
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

        $module.Result.results += @( $result_obj )
    }
}

$module.ExitJson()
