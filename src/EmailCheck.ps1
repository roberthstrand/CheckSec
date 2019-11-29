function checkDomain {
    param (
        [Parameter(Mandatory)]
        [string]
        $Domain
    )
    # Checking whether domain exists
    try {
        Resolve-DnsName $Domain -NoHostsFile -DnsOnly -ErrorAction stop | out-null
    }
    catch {
        Write-error "`n$_"
        Break
    }
    # Checking for an MX record
    $mxCheck = Resolve-DnsName $Domain -type MX -ErrorAction SilentlyContinue
    if (($mxCheck) -and ($mxCheck.type -eq "MX")) {
        $mxCheck = $true
    }
    else {
        $mxCheck = $false
    }
    $result = [PSCustomObject]@{
        MX = $mxCheck
    }
    return $result
}
function Test-SpfRecord {
    [CmdletBinding()]
    param (
        [parameter(Position = 1)]
        [string]
        $SPF,
        [parameter(Position = 0, ValueFromPipeline = $true)]
        [string]
        $Domain
    )
    if ($Domain) {
        $SPF = (Resolve-DnsName $Domain -Type TXT -ErrorAction SilentlyContinue | Where-Object -Property Strings -Like "v=spf1*" | Select-Object -ExpandProperty Strings).replace("{}", "").substring(7)
    }
    [System.Collections.ArrayList]$spfIncludeList = @()
    # Split the SPF, create the counting variables and check every single mechanism
    $spfSplit = $SPF.Split()
    $spfCountInclude = $null
    $spfCountA = $null
    $spfCountPtr = $null
    $spfCountMX = $null
    $spfCountExists = $null
    foreach ($spfMechanism in $spfSplit) {
        if ($spfMechanism -like "include:*") {
            $include = $spfMechanism.split(':') | Select-Object -Last 1
            $spfIncludeList.add($include) | Out-Null
            $spfCountInclude += 1
        }
        elseif ($spfMechanism -like "a:*") {
            $spfCountA += 1
        }
        elseif ($spfMechanism -like "ptr:*") {
            $spfCountPtr += 1
            Write-Warning $spfMechanism
        }
        elseif ($spfMechanism -like "mx:*") {
            $spfCountMX += 1
        }
        elseif ($spfMechanism -like "exists:*") {
            $spfCountExists += 1
        }
        # Warning about PTR
        if ($spfPtr) {
        }
        # All mechanism, qualifier?
        if ($spfMechanism -like "*all") {
            $spfAllQualifier = $spfMechanism.trim("all")
        }
    }
    # Total count of mechanisms that triggers DNS lookups
    $spfTotalLookups = ($spfCountInclude + $spfCountA + $spfCountPtr + $spfCountMX + $spfCountExists)
    # Create a PSCustomObject and return it as the result
    $result = [PSCustomObject]@{
        'TotalLookups' = $spfTotalLookups
        'includes'     = $spfCountInclude
        'a'            = $spfCountA
        'ptr'          = $spfCountPtr
        'mx'           = $spfCountMX
        'exists'       = $spfCountExists
        'All'          = $spfAllQualifier
        'includeList'  = $spfIncludeList
    }
    $result.psobject.TypeNames.Insert(0, "Test-SpfRecord")
    return $result
}
function Test-EmailSecurity {
    param (
        [Parameter(Position = 0, Mandatory)]
        [string]
        $Domain
    )
    # Check whether domain exists & check if there is an MX and set it accordingly
    $checkDomain = checkDomain $Domain
    if ($checkDomain.MX) {
        $domainMX = (Resolve-DnsName $Domain -Type MX -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NameExchange -first 1 -ErrorAction SilentlyContinue).toLower()
    }
    $domainSPF = (Resolve-DnsName $Domain -Type TXT -ErrorAction SilentlyContinue | Where-Object -Property Strings -Like "v=spf1*" | Select-Object -ExpandProperty Strings)
    $domainDmarc = (Resolve-DnsName "_dmarc.$Domain" -type TXT -ErrorAction SilentlyContinue)
    # SPF
    $spfTotalLookups = $null
    if (!$domainSPF) {
        $spfPresent = $false
        $spfList = $null
    }
    else {
        $spfPresent = $true
        [System.Collections.ArrayList]$spfList = @() 
        $spfList.add($domain) | Out-Null
        do {
            $spfTest = Test-SpfRecord -Domain ($spfList | Select-Object -first 1)
            $spfList.RemoveAt(0) | Out-Null
            foreach ($include in $spfTest.includeList) {$spfList.add($include) | Out-Null}
            $spfTotalLookups += $spfTest.TotalLookups
            if ($spfTest.ptr) {
                $spfPtr = $true
                Write-Warning "Using the PTR mechanism is not recommended!"
                Write-Warning "Reference: RFC7208 Section 5.5."
            }
            else {
                $spfPtr = $false
            }
        } while ($spfList)
    }
    # DKIM
    if (($domainMX -like "*outlook.com") -or ($domainSPF -like "*outlook.com*") ) {
        # Exchange Online uses selector1 and selector2._domainkey
        $dkimCheck = Resolve-DnsName selector1._domainkey.$domain -Type Cname -DnsOnly -ErrorAction SilentlyContinue
        if ($dkimCheck) {
            $dkimPresent = $true
        }
        else {
            $dkimPresent = $false
        }
    }
    if ($domainMX -like "*google.com") {
        # G suite uses google._domainkey
        $dkimCheck = Resolve-DnsName google._domainkey.$domain -DnsOnly -ErrorAction SilentlyContinue
        if ($dkimCheck) {
            $dkimPresent = $true
        }
        else {
            $dkimPresent = $false
        }
    }
    if ($domainMX -eq "mail.protonmail.ch") {
        $dkimCheck = Resolve-DnsName protonmail._domainkey.$domain -DnsOnly -ErrorAction SilentlyContinue
        if ($dkimCheck) {
            $dkimPresent = $true
        }
        else {
            $dkimPresent = $false
        }
    }
    # DMARC
    if ($domainDmarc) {
        $domainDmarcPresent = $true
    }
    else {
        $domainDmarcPresent = $false
    }
    if ($domainDmarc.strings -like "*p=reject*") {
        $dmarcPolicy = "reject"
    }
    elseif ($domainDmarc.strings -like "*p=quarantine*") {
        $dmarcPolicy = "quarantine"
    }
    elseif ($domainDmarc.strings -like "*p=none*") {
        $dmarcPolicy = "none"
    }
    else {
        $dmarcPolicy = "N/A"
    }
    # Make a custom object with the results
    $result = [PSCustomObject]@{
        'Domain'          = $Domain
        'MX'              = $domainMX
        'SpfPresent'      = $spfPresent
        'SpfRecord'       = $domainSPF
        'SpfDnsMechanism' = $spfTotalLookups
        'SpfPtrInUse'     = $SpfPtr
        'DkimPresent'     = $dkimPresent
        'DmarcPresent'    = $domainDmarcPresent
        'DmarcPolicy'     = $dmarcPolicy
    }
    if ($result.SpfDnsMechanism -gt 10) {
        Write-Warning "More than 10 DNS lookups will result in PermError, this SPF is currently doing $spfTotalLookups!"
        Write-Warning "Reference: RFC7208 Section 4.6.4."
    }
    return $result
}