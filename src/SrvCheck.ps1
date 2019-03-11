function Test-ComputerSSL {
    param (
        # DNS hostname of the server you want to test. Defaults to localhost.
        [Parameter(Position = 0)]
        [String]
        $ComputerName = "localhost"
    )
    Write-Output $ComputerName
}
function Test-ServerSecurity {
    [CmdletBinding()]
    param (
        # DNS hostname of server you want to check, checks localhost if not present
        [Parameter(Position = 0)]
        [string]
        $ComputerName = "localhost"
    )
    
}