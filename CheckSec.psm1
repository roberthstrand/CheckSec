function checkDomain {
    param (
        [Parameter(Mandatory)]
        [string]
        $domain
    )
    try {
        Write-Verbose "Checking if the domain exists" #-Verbose
        $dnsCheck = Resolve-DnsName $Domain -NoHostsFile -DnsOnly -ErrorAction stop 
        $dnsCheck = $null #clear variable
    }
    catch {
        Write-error "`n$_"
        Break
    }
}
function Test-EmailSecurity {
    param (
        [Parameter(Position = 0, Mandatory)]
        [string]
        $Domain
    )
    # Check whether domain exists
    checkDomain $Domain
    $domainMX = Resolve-DnsName $Domain -Type MX | Select-Object NameExchange -first 1
    $domainSPF = Resolve-DnsName $Domain -Type TXT | Where-Object -Property Strings -Like "v=spf1*"
    $domainDmarc = (Resolve-DnsName "_dmarc.$Domain" -type TXT).strings
    if ($domainSPF) {
        Write-Verbose "SPF, present!" #-Verbose
    }
    if ($domainDmarc -like "*p=reject*") {
        $dmarcPolicy = "reject"
    } elseif ($domainDmarc -like "*p=quarantine*") {
        $dmarcPolicy = "quarantine"
    } elseif ($domainDmarc -like "*p=none*") {
        $dmarcPolicy = "none"
    }
    [PSCustomObject]@{
        Domain          = $Domain;
        MX              = $domainMX.NameExchange;
        SPF             = $domainSPF.strings
        "DMARC Policy"  = $dmarcPolicy
    } | Format-List
}