# Invoke this set of tests in PWSH on 507Ubuntu with these commands:
<#
$config=New-PesterConfiguration
$config.Output.Verbosity='detailed'
$config.Run.Path = '/home/student/AUD507-Labs/pester//Ubuntu.Labs.tests.ps1'
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
      Write-Host "Running nmap full connect scan against Win10 VM (slow)"
      $nmapResults = (sudo nmap -sT -p1-65535 -T4 10.50.7.101)
    }

    It 'Part 4 - Nmap TCP full-connect scan - Open Ports' {
      $openPorts = [int]($nmapResults | grep -c 'open' )
      $openPorts | Should -Be 6
    }

    It 'Part 4 - Nmap TCP full-connect scan - Ports' {
      $portList = ($nmapResults | awk '/open/ {print $1}')
      $portList | Should -Contain '22/tcp'
      $portList | Should -Contain '135/tcp'
      $portList | Should -Contain '139/tcp'
      $portList | Should -Contain '445/tcp'
    }
  }

  Context 'Lab 3.1' {
    It 'Part 1 - lsb_release distribution is correct' {
      (lsb_release -i | awk -F: '{print $2}') |
        Should -BeLike '*Ubuntu'
      (lsb_release -d | awk -F: '{print $2}') |
        Should -BeLike '*Ubuntu 22.04.3 LTS'
      (lsb_release -r | awk -F: '{print $2}') |
        Should -BeLike '*22.04'
      (lsb_release -c | awk -F: '{print $2}') | 
        Should -BeLike '*jammy'
    }

    It 'Part 1 - APT shows missing patches' {
      (apt list --upgradable 2>/dev/null| grep -cv 'Listing' ) |
        Should -BeGreaterOrEqual 1
    }

    It 'Part 1 - SUID count is > 100' {
      $res = (sudo find / -type f -perm /4000 2>/dev/null) 
      $res.Count | Should -BeGreaterThan 100
    }
    #Part 2 is tested via SSH to Alma from Windows VM

    It 'Part 3 - Osquery returns correct OS information' {
      $res = osqueryi "select * from os_version" --json | ConvertFrom-Json
      $res.codename | Should -BeExactly "jammy"
      $res.major | Should -BeExactly 22
      $res.minor | Should -BeExactly 4
      $res.name | Should -BeExactly "Ubuntu"
      $res.patch | Should -BeExactly 0
      $res.platform | Should -BeExactly "ubuntu"
      $res.platform_like | Should -BeExactly "debian"
      $res.version | Should -BeExactly "22.04.3 LTS (Jammy Jellyfish)"
    }

    It 'Part 3 - Osquery returns 52 SUID binaries' {
      $res = (osqueryi "Select * from suid_bin;" --json | ConvertFrom-Json)
      $res.Count | Should -BeExactly 52
    }
  }

  Context 'Lab 3.2' {
    It 'Part 1 - twSetup script is correct' {
      $hash= (Get-FileHash -Algorithm SHA256 -Path /home/student/AUD507-Labs/tripwire/twSetup.sh).Hash
      $hash | Should -BeExactly 'CDF13850E29ED09119AED455038AA2B24704FDBD4FF1A33B85CC66A9C9713421'
    }

    It 'Part 1 - Original tripwire policy is correct' {
      $hash= (Get-FileHash -Algorithm SHA256 -Path /etc/tripwire/twpol.txt).Hash
      $hash | Should -BeExactly '16FE9FF02E0BECE41001A4D6182384792F9023E160C0B0C646D2448726EC3166'
    }

    It 'Part 1 - Corrected tripwire policy is correct' {
      $hash= (Get-FileHash -Algorithm SHA256 -Path /home/student/AUD507-Labs/tripwire/twpol-corrected.txt).Hash
      $hash | Should -BeExactly '9730F635E33FA2D39914CD19258EA691C95796A3DE4503F2F6D88F3023A55A42'
    }

    It 'Part 2 - net.ipv4.tcp_syncookies = 1' {
      $setting = sysctl net.ipv4.tcp_syncookies | awk '{print $3}'
      $setting | Should -BeExactly 1
    }

    It 'Part 2 - kernel.randomize_va_space = 2' {
      $setting = sysctl kernel.randomize_va_space | awk '{print $3}'
      $setting | Should -BeExactly 2
    }

    It 'Part 2 - net.ipv4.ip_forward = 1' {
      $setting = sysctl net.ipv4.ip_forward | awk '{print $3}'
      $setting | Should -BeExactly 1
    }

    It 'Part 3 - Netstat shows port 6379 on loopback' {
      $ports = sudo netstat -ant | awk '/^tcp.*LISTEN[ ]*$/ {print $4}' | sort -n | grep 6379
      $ports | Should -Contain '::1:6379'
      $ports | Should -Contain '127.0.0.1:6379'
    }

    It 'Part 3 - Nmap does not show port 6379' {
      $portCount = (sudo nmap -sT -p 1-65535 10.50.7.20-29 | grep -c 6379)
      $portCount | Should -BeExactly 0
    }

    #Part 4 - Live systemctl tests- no need to test them here

    It 'Part 5 - Osquery shows 76 open TCP ports' {
      $query = "select address,port from listening_ports where protocol=6 order by address,port;"
      $ports = (osqueryi "$query" --json | ConvertFrom-Json)
      $ports.Count | Should -BeExactly 76
    }

    It 'Part 5 - Osquery shows -1 for pids' {
      $query = "select pid,address,port from listening_ports where protocol=6 order by address,port;"
      $ports = (osqueryi "$query" --json | ConvertFrom-Json)
      $ports[0].pid | Should -BeExactly -1
    }

    It 'Part 5 - Osquery shows correct pids with sudo' {
      $query = "select pid,address,port from listening_ports where protocol=6 order by address,port;"
      $ports = (sudo osqueryi "$query" --json | ConvertFrom-Json)
      $ports[0].pid | Should -BeGreaterOrEqual 0
    }

    It 'Part 5 - Osquery shows startup items' {
      $query = "Select name,source,status,path from startup_items;"
      $items = (sudo osqueryi "$query" --json | ConvertFrom-Json)
      $items.Count | Should -BeGreaterThan 0
    }
  }

  Context 'Lab 3.3' {
    #TODO: Check file hashes on all the log files
    AfterAll {
      #Delete the rules we created
      sudo auditctl -D
      #Delete the files we copied
      sudo rm -fR /root/lynis
    }
    It 'Part 1 - Syslog has 28 entries for BuggyBank' {
      $logCount = (grep -ic buggybank /home/student/AUD507-Labs/logs/syslog)
      $logCount | Should -BeExactly 28
    }
    
    It 'Part 1 - Syslog has 130 entries for systemd.*executable' {
      $logCount = (grep -c "systemd.*executable" /home/student/AUD507-Labs/logs/syslog)
      $logCount | Should -BeExactly 130
    }

    It 'Part 1 - Syslog.2.gz has 30 entries for systemd.*executable' {
      $logCount = (zgrep -c "systemd" /home/student/AUD507-Labs/logs/syslog.2.gz)
      $logCount | Should -BeExactly 30
    }

    It 'Part 2 - Journalctl shows at least one prior boot' {
      (journalctl --list-boots).Count | Should -BeGreaterOrEqual 2
    }

    It 'Part 3 - Auditctl shows no initial rules' {
      $ruleList = (sudo auditctl -l)
      $ruleList | Should -BeExactly 'No rules'
    }

    It 'Part 4 - Auditctl rules yield >100 search results' {
      #Do the lab steps:
      sudo auditctl -w /root -k rootHome
      sudo auditctl -w /home/student -k studentHome

      sudo cp -vR /home/student/AUD507-Labs/lynis /root
      sudo chown -R root:root /root/lynis
      sudo chmod +x /root/lynis/lynis

      $logEntries = (sudo ausearch -k rootHome | sudo aureport -f -i)
      $logEntries.Count | Should -BeGreaterThan 100
    }
  }

  Context 'Lab 3.4' {
    It 'Part 1 - Lynis is version 3.0.9' {
      Set-Location /home/student/AUD507-Labs/lynis
      $res = (bash ./lynis show version)
      $res | Should -BeExactly '3.0.9'
    }

    It 'Part 2 - Inspec DIL Ubuntu returns results' {
      Write-Host "Running inspec against Ubuntu (slow)"
      Set-Location /home/student/AUD507-Labs/inspec
      $res = (inspec exec ./cis-dil-benchmark/ --reporter json:- | ConvertFrom-Json)
      ($res.profiles.controls.results | Where-Object Status -eq 'failed').Count |
        Should -BeGreaterThan 0
      ($res.profiles.controls.results | Where-Object Status -eq 'passed').Count |
        Should -BeGreaterThan 0
      ($res.profiles.controls.results | Where-Object Status -eq 'skipped').Count |
        Should -BeGreaterThan 0
    }

    It 'Part 3 - Inspec DIL Alma returns results' {
      Write-Host "Running inspec against Alma (slow)"
      Set-Location /home/student/AUD507-Labs/inspec
      $res = (inspec exec ./cis-dil-benchmark/ -t ssh://student:student@10.50.7.40 --reporter json:- | ConvertFrom-Json)
      ($res.profiles.controls.results | Where-Object Status -eq 'failed').Count |
        Should -BeGreaterThan 0
      ($res.profiles.controls.results | Where-Object Status -eq 'passed').Count |
        Should -BeGreaterThan 0
      ($res.profiles.controls.results | Where-Object Status -eq 'skipped').Count |
        Should -BeGreaterThan 0
    }
  }

  Context 'Lab 4.1'{
    BeforeAll {
      #Create docker bench results file
      sudo bash /home/student/AUD507-Labs/docker-bench-security/docker-bench-security.sh -b -l results.txt

      #pull kube-bench docker container
      docker pull docker.io/aquasec/kube-bench:latest
    }
    AfterAll {
      #Delete the docker bench results file
      sudo rm -f results.txt

      #remove kube-bench docker container
      docker rmi aquasec/kube-bench
    }
    It 'Part 1 - Check docker root directory' {
      $res = (docker info -f '{{ .DockerRootDir }}' | grep -c '/var/lib/docker')
      $res | Should -BeExactly 1
    }

    It 'Part 1 - /var/lib/docker not a mountpoint' {
      $res = (mountpoint /var/lib/docker | grep -c 'is not a mountpoint')
      $res | Should -BeExactly 1
    }

    It 'Part 1 - Docker default bridge disallow traffic between containers' {
      $res = (docker network ls --quiet | xargs docker network inspect --format '{{ .Name}}: {{ .Options }}' 
      | grep -c 'com.docker.network.bridge.enable_icc:true')
      $res | Should -BeExactly 1
    }

    It 'Part 1 - aufs not used as a storage driver' {
      $res = (docker info --format 'Storage Driver: {{ .Driver }}' | grep -c 'aufs')
      $res | Should -BeExactly 0
      $res = (docker info --format 'Storage Driver: {{ .Driver }}' | grep -c 'overlay2')
      $res | Should -BeExactly 1
    }

    It 'Part 1 - daemon.json does not exist' {
      $res = (sudo find / -name "daemon.json" -type f | wc -l)
      $res | Should -BeExactly 0
    }

    It 'Part 2 - Docker-Bench returns passes' {
      $res = (grep "^\[PASS\]" results.txt | wc -l)
      $res | Should -BeGreaterOrEqual 1
    }

    It 'Part 2 - Docker-Bench returns warns' {
      $res = (grep "^\[WARN\]" results.txt | wc -l)
      $res | Should -BeGreaterOrEqual 1
    }

    It 'Part 2 - Docker-Bench returns infos' {
      $res = (grep "^\[INFO\]" results.txt | wc -l)
      $res | Should -BeGreaterOrEqual 1
    }

    It 'Part 2 - Docker-Bench has correct score' {
      $res = (cat ./results.txt | awk '/INFO.*Score:/ {print $3}')
      $res | Should -BeExactly 4
    }

    It 'Part 3 - kubectl client version check' {
      $res = (kubectl version | awk '/Client.*:/ {print $3}')
      $res | Should -BeExactly 'v1.28.4'
    }

    It 'Part 3 - kubectl kustomize version check' {
      $res = (kubectl version | awk '/Kustomize.*:/ {print $3}')
      $res | Should -BeExactly 'v5.0.4-0.20230601165947-6ce0bf390ce3'
    }

    It 'Part 3 - kubectl server version check' {
      $res = (kubectl version | awk '/Server.*:/ {print $3}')
      $res | Should -BeExactly 'v1.28.3'
    }

    It 'Part 3 - kubectl has namespaces' {
      $res = (microk8s kubectl get namespaces | wc -l)
      $res | Should -BeGreaterOrEqual 2
    }

    It 'Part 3 - kubectl has pods in the default namespce' {
      $res = (microk8s kubectl get pods --namespace default | wc -l)
      $res | Should -BeExactly 4
    }

    It 'Part 3 - kubectl has services in the default namespce' {
      $res = (microk8s kubectl get services --namespace default | wc -l)
      $res | Should -BeExactly 4
    }

    It 'Part 3 - kubectl network policy has no resources' {
      $res = (microk8s kubectl get networkpolicy --all-namespaces | grep -c 'No resources found')
      $res | Should -BeExactly 1
    }

    It 'Part 3 - kubectl network policy has no resources' {
      $res = (microk8s kubectl get networkpolicy --all-namespaces | grep -c 'No resources found')
      $res | Should -BeExactly 1
    }

    # TODO: revisit in the future?
    It 'Part 4 - kube-bench returns results' {
      $res = (docker run --pid=host -v /etc:/etc:ro -v /var:/var:ro -v /usr/local/bin/kubectl:/usr/local/mount-from-host/bin/kubectl -v ~/.kube:/.kube -e KUBECONFIG=/.kube/config -t docker.io/aquasec/kube-bench:latest run
        | tail -13 | awk '/ checks / {print $1}' )
      $res.count | Should -BeExactly 8
    }
  }

  Context 'Lab 5.2' {
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
    
    It 'Part 3 - Nmap robots.txt lists ftp directory' {
      $res = (nmap -p80 10.50.7.20 --script http-robots.txt)
      $res | Should -Contain '|_/ftp'
    }

    #Part 4 uses browser plugins and is not tested

    It 'Part 5 - NodeJSScan container exists' {
      (docker image ls | awk '/\// {print $1 $2}') | 
        Should -Contain 'opensecurity/nodejsscan5x7.22.1'
    }
  }
}