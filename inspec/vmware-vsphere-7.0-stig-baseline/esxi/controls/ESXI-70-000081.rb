control 'ESXI-70-000081' do
  title 'The ESXi host must not suppress warnings about unmitigated hyperthreading vulnerabilities.'
  desc  'The L1TF CPU vulnerabilities published in 2018 have patches and mitigations available in vSphere. However, there are performance impacts to these mitigations that require careful thought and planning from the SA before implementation. Until a mitigation is implemented, the UI warning about the lack of a mitigation must not be dismissed lest the SA make the assumption that the vulnerability has been addressed.'
  desc  'rationale', ''
  desc  'check', "
    Fom the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Select the \"UserVars.SuppressHyperthreadWarning\" value and verify that it is set to \"0\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressHyperthreadWarning

    If the \"UserVars.SuppressHyperthreadWarning\" setting is not set to \"0\" or the setting does not exist, this is a finding.
  "
  desc  'fix', "
    Fom the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Select the \"UserVars.SuppressHyperthreadWarning\" value and set it to \"0\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressHyperthreadWarning | Set-AdvancedSetting -Value \"0\"
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000081'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmhostName = input('vmhostName')
  cluster = input('cluster')
  allhosts = input('allesxi')
  vmhosts = []

  unless vmhostName.empty?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless cluster.empty?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.split
  end

  if !vmhosts.empty?
    vmhosts.each do |vmhost|
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name UserVars.SuppressHyperthreadWarning | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '0' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
