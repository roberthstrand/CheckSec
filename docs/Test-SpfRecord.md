# Test-SpfRecord

Check the SPF of a domain or an SPF-record string. As of version 2.0.0, this does not support recursive SPF checking.

## Syntax

```powershell
Test-SpfRecord [-SPF <string>] [-Domain <string>] [<CommonParameters>]
```

## Example

```powershell
Test-SpfRecord -Domain destruktive.one
```

```powershell
Test-SpfRecord -SPF "v=spf1 include:spf.protection.outlook.com -all"
```