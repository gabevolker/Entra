# EntraCBA-EntrustPKI-LoadCACerts.ps1
# Sets up the Entra tenant for DHS PKI supporting Federal PKI
# User executing this script must have Privilege Authentication Administrator role
# This script currently requires a client machine using PowerShell console.
# This script uploads to the Certificate Authorities (Classic) interface
# Warning - this script will replace existing CA entries. Ensure you have run a backup first.

#Installing MgGraph Module - Only need to do this once
if (-not(get-Module -Name Microsoft.Graph.Identity.Signins)) {
    Write-Host -NoNewLine "Installing Microsoft.Graph.Identity.Signins module"
    Install-Module -Name Microsoft.Graph.Identity.Signins -Force
    Import-Module Microsoft.Graph.Identity.Signins
}

#Install additional modules
if (-not(get-Module -Name Microsoft.Graph.Identity.DirectoryManagement)) {
    Write-Host -NoNewLine "Installing Microsoft.Graph.Identity.DirectoryManagement module"
    Install-Module -Name Microsoft.Graph.Identity.DirectoryManagement -Force
    Import-Module Microsoft.Graph.Identity.DirectoryManagement
}

Write-Host " "
Write-Host "Beginning script to load DHS PKI CA Certificates to Entra ID"

#region parameters

##### UPDATE PARAMETERS #####
$defaultWorkingDirectory = "c:\temp"
Write-Host -NoNewline "Setting the Working Directory to "; Write-Host -ForegroundColor Yellow "$((Get-Location).Path)"
Write-Host -NoNewline "Default working directory is "; Write-Host -ForegroundColor DarkYellow "$($defaultWorkingDirectory)"
$confirmation = Read-Host "Do you want to continue? If no, default will be used."
if ($confirmation -eq 'y') {
    $WorkingDirectory = $(Get-Location).Path
} else {
    $WorkingDirectory = $defaultWorkingDirectory
}
Write-Host "Working Directory is set to $WorkingDirectory"

# CRL URLs
# NOTE - For performance reasons you may consider implementing an automated process which pulls the CRLs periodically (e.g. hourly)
# and makes them available in an Azure Storage blob to avoid potential timeouts with Federal PKI infrastructure

#CRL URLs
# NOTE - For performance reasons you may consider implementing an automated process which pulls the CRLs periodically (e.g. hourly)
# and makes them available in an Azure Storage blob to avoid potential timeouts with U.S. Treasury PKI infrastructure

#For Federal Common Policy G2 CA certificate
$CRLFPKI = "http://repo.fpki.gov/fcpca/fcpcag2.crl"
#For US Treasury Root CA - Thumbprint - 52de6628d8c70a9df9e1df94fcd84728b33c05ec
$CRLUSTreas0 = "http://pki.treasury.gov/US_Treasury_Root_CA1.crl"
#For US Treasury Root CA - Thumbprint - 30ee8b72d745da0f6938ed137ac604dcd8a74af0
$CRLUSTreas1 = "http://pki.treasury.gov/US_Treasury_Root_CA.crl"

#Ensure that clients have connectivity to the CRL when using the following values - otherwise uncomment and use the defaults:
#For DHS CA4 - Thumbprint - A31A5DF2F1C1019B9CF5B7CA4E3B26650B9CA93F
$CRLCA4 = "http://pki.dimc.dhs.gov/DHS_CA2.crl"
#For DHS CA4 - Thumbprint - 58085a64e181573f4fd917c5c021eb1cf344dd5f
$CRLCA41 = "http://pki.dimc.dhs.gov/DHS_CA3.crl"
#For DHS CA4 - Thumbprint - (New) - d8624442ccc91753aca89698f2cbcdf59f32d3f1
$CRLCA42 = "http://pki.dimc.dhs.gov/DHS_CA4.crl"

#Uncomment to use EVPS endpoints or update to use custom blob store hosting DHS CA4 CRLs
$CRLCA4 = "http://epvs.blob.core.usgovcloudapi.net/crl/DHS_CA2.crl"
$CRLCA41 = "http://epvs.blob.core.usgovcloudapi.net/crl/DHS_CA3.crl"
$CRLCA42 = "http://epvs.blob.core.usgovcloudapi.net/crl/DHS_CA4.crl"

#Includes DHS CA4 rekey certificate
$CertFileURL = "https://pki.treas.gov/dhsca_fullpath.p7b"

$CertFileURLs = [ordered]@{}
$CertFileURL1 = "https://pki.treas.gov/dhsca_fullpath.p7b"
$CertFileURLs.Add("dhsca_fullpath.p7b",$CertFileURL1)

#Mapping for CRL Lookups - This needs to be updated if any of the chain certificates are updated
$IDCACRLs = [ordered]@{}
$IDCACRLs.Add("FPKI",$CRLFPKI)
$IDCACRLs.Add("UST0",$CRLUSTreas0)
$IDCACRLs.Add("UST1",$CRLUSTreas1)
$IDCACRLs.Add("CA4",$CRLCA4)
$IDCACRLs.Add("CA41",$CRLCA41)
$IDCACRLs.Add("CA42",$CRLCA42)

#Array used to store Certificate Chain being uploaded
$CAChain = @()

#endregion

#region functions

function Add-HashtableToArray {
    param (
        [ref]$Array,
        [byte[]]$Certificate,
        [bool]$IsRootAuthority,
        [string]$crl
    )

    $newHashtable = @{
        Certificate        = $Certificate
        IsRootAuthority       = $IsRootAuthority
        CertificateRevocationListUrl = $crl
    }

    $Array.Value += $newHashtable
}

function GetCertificateFiles {
    Param($CertFileURL,$WorkingDirectory,$WorkingFile)
    $outfile = $("$WorkingDirectory\$WorkingFile")
    if($outfile.EndsWith(".p7c")) {
        $outfile = $outfile.Replace(".p7c",".p7b");
    }
    if($outfile.EndsWith(".crt")) {
        $outfile = $outfile.Replace(".crt",".cert");
    }
    Invoke-WebRequest -Uri $CertFileURL -OutFile $outfile
    Return $outfile
}

function BuildCertificateAuthorityChain {
    Param([array]$IDCerts,[hashtable]$IDCACrls)
    
    foreach ($cert in $IDCerts) {
        $root = $cert.Subject -match "FPKI"

        #Locate the CRL value
        if($cert.Subject -match "FPKI") {
            $indicator = "FPKI"
        }
        if($cert.Subject -match "CA4") {
            if($cert.Thumbprint -match "A31A5DF2F1C1019B9CF5B7CA4E3B26650B9CA93F") {
                $indicator = "CA4"
            } elseif($cert.Thumbprint -match "58085a64e181573f4fd917c5c021eb1cf344dd5f") {
                $indicator = "CA41"
            } else {
                $indicator = "CA42"
            }            
        }
        if($cert.Subject -match "Treasury") {
            if($cert.Issuer -match "FPKI") {
                $indicator = "UST0"
            } else {
                $indicator = "UST1"            
            }
        }
        $crl = $IDCACrls[$indicator]
        
        Write-Host -NoNewline -foregroundcolor White "Subject:    "; Write-Host -foregroundcolor Yellow "$($cert.Subject)"
        Write-Host -NoNewline -foregroundcolor White "Thumbprint:    "; Write-Host -foregroundcolor Yellow "$($cert.Thumbprint)"
        Write-Host -NoNewline -foregroundcolor White "CRL:    "; Write-Host -foregroundcolor Yellow "$($crl)"
        Write-Host -NoNewline -foregroundcolor White "isRoot:    "; Write-Host -foregroundcolor Yellow "$($root)"
        Write-Host " "
        
        Try {
	    Add-HashtableToArray -Array ([ref]$CAChain) -Certificate $cert.RawData -IsRootAuthority $root -crl $crl

        } catch [exception] {
            write-host -ForegroundColor Cyan "Certificate already exists in Entra ID CA Configuration"
	        write-host $_.Exception
        }
    }
}

function UploadCertificateAuthorityChain {
    Param([ref]$CertificateAuthorities)

    # Define the input object for the new configuration
    $TenantId = $(Get-MgOrganization).Id
    
    $certificateBasedAuthConfig = @{
        Id = "29728ade-6ae4-4ee9-9103-412912537da5"  # Fixed ID for certificate-based auth config
        
        CertificateAuthorities = $CertificateAuthorities.Value
    }

    #Write-Host -foregroundcolor Red "Dumping Certificate Chain..."
    #$certificateBasedAuthConfig.CertificateAuthorities

    # Create the certificate-based auth configuration
    $out = New-MgOrganizationCertificateBasedAuthConfiguration -OrganizationId $TenantId -BodyParameter $certificateBasedAuthConfig

}

function GetConfigDetails {
    $TenantId = $(Get-MgOrganization).Id
    $CertIdConfig = Get-MgOrganizationCertificateBasedAuthConfiguration -OrganizationId $TenantId -Property *

    return $CertIdConfig
}
#endregion

###### Begin Script ######

# Get Certificates
ForEach($item in $CertFileURLs.Keys) {

    Write-Host -NoNewline -foregroundcolor Magenta "Reading Certificate Files from "; Write-Host -foregroundcolor Yellow "$($CertFileUrls[$item])"
    Try {
        $p7bfile = GetCertificateFiles -CertFileURL "$($CertFileUrls[$item])" -WorkingDirectory $WorkingDirectory -WorkingFile $item
    } Catch {
        Write-Host -ForegroundColor Red "Unable to download the Certificate package, exiting script.";
        Exit;
    }
    #$DebugPreference = "Inquire"
    #Write-Debug -Message "Continue to process next certificate?" -Debug
    #$DebugPreference = "SilentlyContinue"

    # Import Certificates for usage
    Write-Host -NoNewline -foregroundcolor Magenta "Importing Certificate to Local Machine..."; Write-Host -ForegroundColor Yellow "$p7bfile"
    $PKICerts = Import-Certificate -FilePath $p7bfile -CertStoreLocation Cert:\LocalMachine\My
   

    #Ensure that you are connected to Graph API
    if(-not(Get-MgOrganization)) {
        #Connect to Graph API with required Scopes
        Connect-MgGraph -scopes "Directory.ReadWrite.All","Organization.ReadWrite.All"
    }

    #Build Certificate Chain
    Write-Host -foregroundcolor Magenta "Building the Certificates Chain..."
    BuildCertificateAuthorityChain -IDCerts $PKICerts -IDCACrls $IDCACRLs
    
}
    Write-Host -foregroundcolor Magenta "Uploading Certificates into Entra ID..."
    UploadCertificateAuthorityChain -CertificateAuthorities ([ref]$CAChain)
    Write-Host -ForegroundColor Cyan "Completed."
    Write-Host " "
    Write-Host -ForegroundColor Magenta "Attempting to Read the new Certificate Authorities Configuration..."	
    (GetConfigDetails).CertificateAuthorities | Format-List Issuer,IsRootAuthority,IssuerSki,CertificateRevocationListUrl
    Write-Host -NoNewline "Run "
    Write-Host -NoNewline -foregroundcolor Yellow "Get-MgOrganizationCertificatebasedAuthConfiguration"
    Write-Host " after a couple minutes to validate presence of the imported certificates if there are no immediate results."
