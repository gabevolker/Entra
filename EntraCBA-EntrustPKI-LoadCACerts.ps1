# EntraCBA-EntrustPKI-LoadCACerts.ps1
# Sets up the Entra tenant for Entrust PKI supporting Federal PKI
# User executing this script must have Privilege Authentication Administrator role
# This script currently requires a client machine using PowerShell console.

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

Write-Host "Beginning script to load EntrustPKI CA Certificates to Entra ID"

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

#For Federal Common Policy G2 CA certificate - Thumbprint - 99b4251e2eee05d8292e8397a90165293d116028
$CRLFPKI = "http://repo.fpki.gov/fcpca/fcpcag2.crl"

#For Entrust Managed Services Root CA - Thumbprint - 07f5dc58f83778d5b5738a988292c00a674a0f40
#Chains up to -- 99b4251e2eee05d8292e8397a90165293d116028
$CRLEntrustRootCA0 = "http://rootweb.managed.entrust.com/CRLs/EMSRootCA3.crl"
#For Entrust Managed Services Root CA - Thumbprint - 855d98c924b3ee6216b1b8e25b4342f70565c394
#Chains up to -- 07f5dc58f83778d5b5738a988292c00a674a0f40
$CRLEntrustRootCA1 = "http://rootweb.managed.entrust.com/CRLs/EMSRootCA2.crl"
#For Entrust Managed Services SSP CA - Thumbprint - d6be623683f2b47e94452c04fa1ab3ab631e83eb
#Chains up to -- 99b4251e2eee05d8292e8397a90165293d116028
$CRLEntrustRootCA2 = "http://rootweb.managed.entrust.com/CRLs/EMSRootCA4.crl"

#For Entrust Managed Services SSP CA - Thumbprint - 722e8abbe6b66e47d1bcec3c7ec47aa5bbe4d3c5
#Chains up to -- 07f5dc58f83778d5b5738a988292c00a674a0f40
$CRLEntrustSSPCA0 = "http://sspweb.managed.entrust.com/CRLs/EMSSSPCA3.crl"
#For Entrust Managed Services SSP CA - Thumbprint - dec01bf40c153fbc38bf2ca766b04f9dfbda3064
#Chains up to -- 855d98c924b3ee6216b1b8e25b4342f70565c394
$CRLEntrustSSPCA1 = "http://sspweb.managed.entrust.com/CRLs/EMSSSPCA2.crl"
#For Entrust Managed Services SSP CA - Thumbprint - 19fea49c468760edce9600a9da9657b484734d24
#Chains up to -- d6be623683f2b47e94452c04fa1ab3ab631e83eb
$CRLEntrustSSPCA2 = "http://sspweb.managed.entrust.com/CRLs/EMSSSPCA4.crl"

#Full Entrust PKI Certificate chain includes Federal Common Policy G2, Entrust Roots and SSP CAs
#Note - this does not contain Derived Credential CAs

$CertFileURLs = [ordered]@{}
$CertFileURL1 = "http://repo.fpki.gov/fcpca/fcpcag2.crt"
$CertFileURL2 = "http://rootweb.managed.entrust.com/AIA/CertsIssuedToEMSRootCA.p7c"
$CertFileURL3 = "http://sspweb.managed.entrust.com/AIA/CertsIssuedToEMSSSPCA.p7c"
$CertFileURLs.Add("fcpcag2.crt",$CertFileURL1)
$CertFileURLs.Add("CertsIssuedToEMSRootCA.p7c",$CertFileURL2)
$CertFileURLs.Add("CertsIssuedToEMSSSPCA.p7c",$CertFileURL3)


#Mapping for CRL Lookups - This needs to be updated if any of the chain certificates are updated
$IDCACRLs = [ordered]@{}
$IDCACRLs.Add("FPKI",$CRLFPKI)
$IDCACRLs.Add("EMR0",$CRLEntrustRootCA0)
$IDCACRLs.Add("EMR1",$CRLEntrustRootCA1)
$IDCACRLs.Add("EMR2",$CRLEntrustRootCA2)
$IDCACRLs.Add("EMS0",$CRLEntrustSSPCA0)
$IDCACRLs.Add("EMS1",$CRLEntrustSSPCA1)
$IDCACRLs.Add("EMS2",$CRLEntrustSSPCA2)

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
        if($cert.Subject -match "SSP") {
            if($cert.Thumbprint -match "722e8abbe6b66e47d1bcec3c7ec47aa5bbe4d3c5") {
                $indicator = "EMS0"
            } elseif($cert.Thumbprint -match "dec01bf40c153fbc38bf2ca766b04f9dfbda3064") {
                $indicator = "EMS1"
            } elseif($cert.Thumbprint -match "19fea49c468760edce9600a9da9657b484734d24") {
                $indicator = "EMS2"
            } else {
                Continue;
            } 
        }
        if($cert.Subject -match "Root") {
            if($cert.Thumbprint -match "07f5dc58f83778d5b5738a988292c00a674a0f40") {
                $indicator = "EMR0"
            } elseif($cert.Thumbprint -match "855d98c924b3ee6216b1b8e25b4342f70565c394") {
                $indicator = "EMR1"
            } elseif($cert.Thumbprint -match "d6be623683f2b47e94452c04fa1ab3ab631e83eb") {
                $indicator = "EMR2"
            } elseif($cert.Thumbprint -match "ce3ff28c3e4491c6a76f936999fb6e4ed24de3ec") {
                #Write-Host -ForegroundColor Green "Skipping Unused Root Certificate";
                Continue;
            }
            else { Continue; }
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
    (GetConfigDetails).CertificateAuthorities | FL Issuer,IsRootAuthority,IssuerSki,CertificateRevocationListUrl
    Write-Host -NoNewline "Run "
    Write-Host -NoNewline -foregroundcolor Yellow "Get-MgOrganizationCertificatebasedAuthConfiguration"
    Write-Host " after a couple minutes to validate presence of the imported certificates if there are no immediate results."
