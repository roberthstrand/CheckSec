# Test-EmailSecurity

Checks and verifies that a domain is set up with email security mechanisms like SPF, DKIM and DMARC.

Note that DKIM is only supported if the domain uses known providers like Exchange Online, Google and ProtonMail as the DNS record for DKIM aren't necessarily static.

## Syntax

```powershell
Test-EmailSecurity -Domain <string> [<CommonParameters>]
```

## Example

```powershell
Test-EmailSecurity destruktive.one
```

If you want to check more than one domain, you could make an array and use *foreach* to check one by one.

```powershell
$domains = @("Example.com","Example.org","destruktive.one")

$domains | foreach {Test-EmailSecurity $_}
```