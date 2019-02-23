# Get-EmailDetail

Checks and verifies that a domain is set up with email security mechanisms like SPF, DKIM and DMARC.

Note that DKIM is only supported if the domain uses known providers like Exchange Online og Google, as the DNS record for DKIM aren't static.

## Syntax

```powershell
Get-EmailDetail -Domain <string> [<CommonParameters>]
```

## Example

```powershell
Get-EmailDetail destruktive.one
```

If you want to check more than one domain, you could make an array and use *foreach* to check one by one.

```powershell
$domains = @("Example.com","Example.org","destruktive.one")

$domains | foreach {Get-EmailDetail $_}
```