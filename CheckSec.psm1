function checkDomain {
    param (
        [Parameter(Mandatory)]
        [string]
        $domain
    )
    try {
        Write-Verbose "Checking if the domain exists" #-Verbose
        Resolve-DnsName $Domain -NoHostsFile -DnsOnly -ErrorAction stop | out-null
    }
    catch {
        Write-error "`n$_"
        Break
    }
}
function spfExtractor {
    param (
        # SPF TXT value
        [Parameter(Position = 0,Mandatory)]
        [string]
        $SpfTxt
    )
    $SpfCounter = $SpfTxt.substring(7)
    $SpfCounter = $SpfCounter -split " "
    $global:SpfCounter = ($SpfCounter.count - 1)
    if ($SpfTxt -like "*PTR:*") {
        $global:SpfPtr = $true
    } else {
        $global:SpfPtr = $false
    }
}
function Get-EmailDetail {
    param (
        [Parameter(Position = 0, Mandatory)]
        [string]
        $Domain
    )
    # Check whether domain exists
    checkDomain $Domain
    $domainMX = Resolve-DnsName $Domain -Type MX | Select-Object NameExchange -first 1
    $domainSPF = Resolve-DnsName $Domain -Type TXT | Where-Object -Property Strings -Like "v=spf1*" #TODO: få bort strings
    $domainDmarc = Resolve-DnsName "_dmarc.$Domain" -type TXT -ErrorAction SilentlyContinue
    if ($domainSPF) {
        Write-Verbose "SPF, present!"
        $spfPresent = $true
    } else {
        $spfPresent = $false
    }
    if ($domainDmarc) {
        $domainDmarcPresent = $true
    } else {
        $domainDmarcPresent = $false
    }
    if ($domainDmarc.strings -like "*p=reject*") {
        $dmarcPolicy = "reject"
    } elseif ($domainDmarc.strings -like "*p=quarantine*") {
        $dmarcPolicy = "quarantine"
    } elseif ($domainDmarc.strings -like "*p=none*") {
        $dmarcPolicy = "none"
    } else {
        $dmarcPolicy = "N/A"
    }
    [PSCustomObject]@{
        'Domain'          = $Domain
        'MX'              = $domainMX.NameExchange
        'SpfPresent'     = $spfPresent
        'SpfRecord'      = $domainSPF.strings
        'DmarcPresent' = $domainDmarcPresent
        'DmarcPolicy'  = $dmarcPolicy
    }
}
function Test-EmailSecurity {
    param (
        [Parameter(Position = 0, Mandatory)]
        [string]
        $Domain
    )
    $emailDetail = Get-EmailDetail $Domain
    # SPF
    if ($emailDetail.SpfRecord[0]){
        spfExtractor -SpfTxt $emailDetail.SpfRecord[0]
    }
    Write-Output "Checking SPF"
    if ($global:SpfPtr) {
        Write-Warning "Using the PTR mechanism is not recommended!"
        Write-Warning "Reference: RFC7208 Section 5.5."
    }
    if ($global:spfCounter -gt 10) {
        Write-Warning "Too many DNS mechanics"
    }
    # DKIM
    Write-Output "Checking DKIM"
    if ($emailDetail.MX -like "*outlook.com") {
        try {
            Resolve-DnsName selector1._domainkey.$domain -DnsOnly -ErrorAction SilentlyContinue | Out-Null
            $dkimPresent = $true
        }
        catch {
            $dkimPresent = $false
        }
    }
    [PSCustomObject]@{
        "SPF"       = $emailDetail.SpfPresent
        "Mechanics" = $global:spfCounter
        "PTR"       = $global:SpfPtr
        "DKIM"      = $dkimPresent
    }
}