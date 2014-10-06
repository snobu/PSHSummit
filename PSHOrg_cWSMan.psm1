# cWSMan DSC Resource
# -------------------
# Description: WSMan (WS-Management) Desired State Configuration
#              Web Services-Management (WS-Management) is a DMTF open standard
#              defining a SOAP-based protocol for the management of servers,
#              devices, applications and various Web services. 
#
# Authors: Adrian Calinescu <foo@snobu.org>
#          Stein Petersen, <steinpetersen@gmail.com>
#          Simon Bromberger <simon.bg@outlook.com>
#
# WMF4+ only
#
# TO DO: Make a key out of one of the params for the .schema.mof (Set as mandatory and notnull)
#        Be WAY more verbose
#        Module manifest
#        Configuration Sample (Resource Definition)
#        .schema.mof

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
	param
	(   
        [Parameter(Mandatory=$False)]
        [ValidateRange(1, 429467295)]
        [Int64]$MaxConcurrentOperationsPerUser,

        [Parameter(Mandatory=$False)]
        [Boolean]$AllowUnencrypted,

        [Parameter(Mandatory=$False)]
        [Boolean]$AllowRemoteAccess,

        [Parameter(Mandatory=$False)]
        [Boolean]$EnableCompatibilityHttpListener,

        [Parameter(Mandatory=$False)]
        [Boolean]$EnableCompatibilityHttpsListener,

        [Parameter(Mandatory=$False)]
        [String]$IPv4Filter,

        [Parameter(Mandatory=$False)]
        [String]$IPv6Filter,

        [Parameter(Mandatory=$False)]
        [String]$CertificateThumbprint,

        [Parameter(Mandatory=$False)]
        [Boolean]$Basic,

        [Parameter(Mandatory=$False)]
        [Boolean]$Kerberos,

        [Parameter(Mandatory=$False)]
        [Boolean]$Certificate,

        [Parameter(Mandatory=$False)]
        [Boolean]$Negotiate,

        [Parameter(Mandatory=$False)]
        [Boolean]$CredSSP,

        [Parameter(Mandatory=$False)]
        [ValidateSet('Strict', 'Relaxed', 'None')]
        [String]$CbtHardeningLevel,

        [Parameter(Mandatory=$False)]
        [String]$HTTP,
        
        [Parameter(Mandatory=$False)]
        [String]$HTTPS

	)
	  
    #Get all params out of the cmdlet
    [string[]]$AllParam = $PSCmdlet.MyInvocation.MyCommand.Parameters.Keys
    #Get Common params (provided by CmdletBinding)
    [string[]]$CommonParam = ([System.Management.Automation.Internal.CommonParameters].GetProperties()).Name

    #The diff is the params we really specified
    $MyProps = (Compare-Object -ReferenceObject $AllParam -DifferenceObject $CommonParam -ErrorAction SilentlyContinue).InputObject
    
    $almostHash = Get-ChildItem -ErrorAction SilentlyContinue -Recurse WSMan:\localhost\Service | Select Name, Value
    $hash = [Ordered]@{}
    
    foreach ($key in $almostHash) {
        if ($MyProps -Contains $key.Name) {
            $hash.Add($key.Name, $key.Value)
        }
    }

    #return the hashtable
    $hash

} #Get-TargetResource



function Set-TargetResource
{
    [CmdletBinding()]
	param
	(   
        [Parameter(Mandatory=$False)]
        [ValidateRange(1, 429467295)]
        [Int64]$MaxConcurrentOperationsPerUser = 240000,

        [Parameter(Mandatory=$False)]
        [Boolean]$AllowUnencrypted = $True,

        [Parameter(Mandatory=$False)]
        [Boolean]$AllowRemoteAccess = $True,

        [Parameter(Mandatory=$False)]
        [Boolean]$EnableCompatibilityHttpListener,

        [Parameter(Mandatory=$False)]
        [Boolean]$EnableCompatibilityHttpsListener,

        [Parameter(Mandatory=$False)]
        [String]$IPv4Filter = '*',

        [Parameter(Mandatory=$False)]
        [String]$IPv6Filter = '*',

        [Parameter(Mandatory=$False)]
        [String]$CertificateThumbprint,

        [Parameter(Mandatory=$False)]
        [Boolean]$Basic = $False,

        [Parameter(Mandatory=$False)]
        [Boolean]$Kerberos = $True,

        [Parameter(Mandatory=$False)]
        [Boolean]$Certificate = $False,

        [Parameter(Mandatory=$False)]
        [Boolean]$Negotiate = $True,

        [Parameter(Mandatory=$False)]
        [Boolean]$CredSSP = $False,

        [Parameter(Mandatory=$False)]
        [ValidateSet('Strict', 'Relaxed', 'None')]
        [String]$CbtHardeningLevel = 'Relaxed',

        [Parameter(Mandatory=$False)]
        [String]$HTTP = '5985',
        
        [Parameter(Mandatory=$False)]
        [String]$HTTPS = '5986'
    )

    #if Get-NetConnectionProfile returns Public then it's a NO go!
    if ((Get-NetConnectionProfile).NetworkCategory -Contains 'Public') {
        "One or more Network Interfaces are set to Public. " +
        "It's probably not the brightest idea to just go set " +
        "them to Private for you, so you go fix that and " +
        "then run this thing again." | Write-Warning -Verbose
        
        #can we break or do we break the execution altogether?
        break
    } 

    #Get all params out of the cmdlet
    [string[]]$AllParam = $PSCmdlet.MyInvocation.MyCommand.Parameters.Keys
    #Get Common params (provided by CmdletBinding)
    [string[]]$CommonParam = ([System.Management.Automation.Internal.CommonParameters].GetProperties()).Name
    
    #The diff is the params we really specified
    $MyProps = (Compare-Object -ReferenceObject $AllParam -DifferenceObject $CommonParam -ErrorAction SilentlyContinue).InputObject
        
    foreach ($key in $MyProps) {
           $Name = (Get-Variable $key).Name
           $Value = (Get-Variable $key).Value
           Write-Verbose "Setting $Name to $Value.."
           $which = Get-ChildItem -ErrorAction SilentlyContinue WSMan:\localhost\Service -Recurse -Include $Name | select PSPath
           Set-Item $which.PSPath -Value $Value -Force -ErrorAction SilentlyContinue
    }
} #Set-TargetResource
        


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
	param
	(   
        [Parameter(Mandatory=$False)]
        [ValidateRange(1, 429467295)]
        [Int64]$MaxConcurrentOperationsPerUser = 240000,

        [Parameter(Mandatory=$False)]
        [Boolean]$AllowUnencrypted = $True,

        [Parameter(Mandatory=$False)]
        [Boolean]$AllowRemoteAccess = $True,

        [Parameter(Mandatory=$False)]
        [Boolean]$EnableCompatibilityHttpListener,

        [Parameter(Mandatory=$False)]
        [Boolean]$EnableCompatibilityHttpsListener,

        [Parameter(Mandatory=$False)]
        [String]$IPv4Filter = '*',

        [Parameter(Mandatory=$False)]
        [String]$IPv6Filter = '*',

        [Parameter(Mandatory=$False)]
        [String]$CertificateThumbprint,

        [Parameter(Mandatory=$False)]
        [Boolean]$Basic = $False,

        [Parameter(Mandatory=$False)]
        [Boolean]$Kerberos = $True,

        [Parameter(Mandatory=$False)]
        [Boolean]$Certificate = $False,

        [Parameter(Mandatory=$False)]
        [Boolean]$Negotiate = $True,

        [Parameter(Mandatory=$False)]
        [Boolean]$CredSSP = $False,

        [Parameter(Mandatory=$False)]
        [ValidateSet('Strict', 'Relaxed', 'None')]
        [String]$CbtHardeningLevel = 'Relaxed',

        [Parameter(Mandatory=$False)]
        [String]$HTTP = '5985',
        
        [Parameter(Mandatory=$False)]
        [String]$HTTPS = '5986'
    )
	  
    #Get all params out of the cmdlet
    [string[]]$AllParam = $PSCmdlet.MyInvocation.MyCommand.Parameters.Keys
    #Get Common params (provided by CmdletBinding)
    [string[]]$CommonParam = ([System.Management.Automation.Internal.CommonParameters].GetProperties()).Name

    #The diff is the params we really specified
    $MyProps = (Compare-Object -ReferenceObject $AllParam -DifferenceObject $CommonParam -ErrorAction SilentlyContinue).InputObject
    
    $almostHash = Get-ChildItem -ErrorAction SilentlyContinue -Recurse WSMan:\localhost\Service | Select Name, Value

    $hashCurrent = @{}    
    foreach ($key in $almostHash) {
        if ($MyProps -Contains $key.Name) {
            $hashCurrent.Add($key.Name, $key.Value)
        }
    }

    $hashDesired = @{}
    foreach ($key in $MyProps) {
        $hashDesired.Add((Get-Variable $key).Name, ((Get-Variable $key).Value))
    }

    $hashCurrentAsObj = ([PSCustomObject]$hashCurrent).PSObject.Properties | select Name, Value
    $hashDesiredAsObj = ([PSCustomObject]$hashDesired).PSObject.Properties | select Name, Value

    $exitFlag = $False
    #if Compare-Object returns nothing we're good
    if (!(Compare-Object -ReferenceObject $hashCurrentAsObj -DifferenceObject $hashDesiredAsObj -Property Name, Value -ErrorAction SilentlyContinue).Value) {
        $exitFlag = $True
    }
    else {
        #Why the test failed
        $reason = Compare-Object -ReferenceObject $hashCurrentAsObj -DifferenceObject $hashDesiredAsObj -Property Name, Value
        $reason.ForEach({
            $_.ToString()
            Write-Verbose -Message $_
        })
    }

    $exitFlag

} #Test-TargetResource

#Export-ModuleMember -function *-TargetResource