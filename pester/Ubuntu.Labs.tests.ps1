# Invoke this set of tests in PWSH on 507Ubuntu with these commands:
<#
Set-Location /home/student/AUD507-Labs/pester/
$config=New-PesterConfiguration
$config.Output.Verbosity='detailed'
$config.Run.Path = './Ubuntu.Labs.tests.ps1'
Invoke-Pester -Configuration $config
#>

Describe '507 Labs'{
  BeforeDiscovery {
    #If the AWS config files are not there, then skip the AWS tests
    if( -not ( (Test-Path -Type Leaf -Path /home/student/.aws/credentials) -or (Test-Path -Type Leaf -Path /home/student/.aws/config) ) ) {
      $skipAWS = $true
    }
    else {
      #Skip the Cloud Services tests if there are no good AWS credentials
      $userARN = (aws sts get-caller-identity | jq '.Arn')
      if( $userARN -notlike '*student*'){
        $skipAWS = $true
      }
    }

    #If the Azure configuration is not there, then skip the Azure tests
    $azSubCount = (Get-Content /home/student/.azure/azureProfile.json | ConvertFrom-Json).Subscriptions.Count
    if( $azSubCount -lt 1) {
      Write-Host "Skipping Azure tests because config files do not exist"
      $skipAzure = $true
    } 
  }

  Context 'Lab 1.2' {
    It 'Part 1 - Host count with ARP' {
      $hostCount = [int](sudo nmap -sn -n 10.50.7.20-110 | grep -c '^Host is up' )
      $hostCount | Should -BeGreaterOrEqual 10
    }

    It 'Part 1 - Host count without ARP' {
      $hostCount = [int](sudo nmap -sn -n --disable-arp-ping 10.50.7.20-110 | grep -c '^Host is up' )
      $hostCount | Should -BeGreaterOrEqual 9
    }

    It 'Part 2 - Stealth scan gets filtered port 80' {
      $portCount = [int]( sudo nmap -sS -p 80 10.50.7.22-29 | grep -c 'filtered' )
      $portCount | Should -Be 1
    }

    It 'Part 2 - Connect scan gets open port 80' {
      $portCount = [int]( sudo nmap -sT -p 80 10.50.7.22-29 | grep -c 'open' )
      $portCount | Should -Be 4
    }
    
    It 'Part 3 - OpenSSH version is 8.9p1' {
      $portCount = [int]( sudo nmap -sV -sT -p 22 10.50.7.20-25 | grep -c '8.9p1' )
      $portCount | Should -Be 6
    }
  
    It 'Part 3 - Kubectl shows 4 services' {
      $portList = ( microk8s kubectl get services | awk -F: '/NodePort/ {print $2}' | sed -e 's/\/.*//' )
      $portList | Should -Contain 30020
      $portList | Should -Contain 30022
      $portList | Should -Contain 30023
      $portList | Should -Contain 30024
    }

    It 'Part 3 - K8s Apache versions correct' {
      $verList = ( sudo nmap -sT -p30022-30024 -sV 127.0.0.1 | awk '/Apache/ {print $6}' )
      $verList[0] | Should -Be '2.4.7'
      $verList[1] | Should -Be '2.4.7'
      $verList[2] | Should -Be '2.4.25'
    }
  }

  Context 'Lab 2.2' {

    BeforeAll{
      $nmapResults = (sudo nmap -sT -T4 -p1-65535 10.50.7.101)
    }

    It 'Part 4 - NMap TCP full-connect scan - Open Ports' {
      $openPorts = [int]($nmapResults | grep -c 'open' )
      $openPorts | Should -Be 6
    }

    It 'Part 4 - NMap TCP full-connect scan - Ports' {
      $portList = ($nmapResults | awk '/open/ {print $1}')
      $portList | Should -Contain '22/tcp'
      $portList | Should -Contain '135/tcp'
      $portList | Should -Contain '139/tcp'
      $portList | Should -Contain '445/tcp'
    }
  }

  Context 'Lab 5.2'{
    It 'Part 2 - Nmap returns self-signed cert' {
      $issuerInfo = (sudo nmap -p443 10.50.7.20 --script ssl-cert | awk '/Issuer:/ {print$3}')
      $issuerInfo | Should -BeLike '*juiceshop.5x7.local*'
    }

    It 'Part 2 - Nmap returns TLS v1.2 and v1.3' {
      $versionList = (nmap -p443 10.50.7.20 --script ssl-enum-ciphers | awk '/TLSv[0-9]/ {print $2}' | sed -e 's/://g')
      $versionList.Count | Should -BeExactly 2
      $versionList | Should -Contain 'TLSv1.2'
      $versionList | Should -Contain 'TLSv1.3'
    }

    It 'Part 3 - Nmap returns correct headers' {
      $res = nmap -p80 10.50.7.20 --script http-headers
      $res | grep -c 'Strict-Transport-Security' |
        Should -BeExactly 0
      $res | grep -c 'Content-Security-Policy' |
        Should -BeExactly 0
      $res | grep -c 'X-Frame-Options' |
        Should -BeExactly 1
    }
  }
}