require 'acceptance_spec_helper'

profile = ENV.fetch('GOGS_TARGET_PROFILE', 'gogs_hooks')
raise ArgumentError, "Unknown Gogs profile: #{profile}" unless %w[gogs_hooks gogs_rebase gogs_rebase_fixed].include?(profile)

RSpec.describe 'Native Gogs repository execution targets' do
  include_context 'Gogs target'

  if profile == 'gogs_hooks'
    %w[legacy prefix].each do |service|
      it "detects #{service} passively without implying authenticated hook permission" do
        expect(gogs_invoke(service, {}, action: 'check')).to include('The target appears to be vulnerable', 'Gogs found')
      end
    end

    it 'does not detect the unrelated Apache root as Gogs' do
      expect(gogs_invoke('prefix', { 'TARGETURI' => '/' }, action: 'check')).to include('Target does not appear to be running Gogs.')
    end

    it 'does not detect a missing application path as Gogs' do
      expect(gogs_invoke('legacy', { 'TARGETURI' => '/module-target-absent/' }, action: 'check')).to include('Target does not appear to be running Gogs.')
    end

    it 'executes administrator hook commands twice on the legacy root' do
      gogs_command('legacy')
    end

    it 'executes explicitly granted ordinary-user hooks twice through the genuine subpath' do
      gogs_command('prefix', { 'USERNAME' => 'lab-hook' })
    end

    it 'opens two real legacy Bash sessions with native UID and process shutdown proof' do
      gogs_session('legacy', 'cmd/unix/reverse_bash')
    end

    it 'uses the ordinary Linux x64 Meterpreter Bourne dropper twice through the subpath' do
      gogs_session('prefix', 'linux/x64/meterpreter/reverse_tcp', target: 1)
    end

    it 'refuses two ordinary users without the native hook grant' do
      gogs_refused('prefix', { 'USERNAME' => 'lab-user' }, expected: 'Post-receive hook creation failure')
    end

    it 'refuses a rejected web password twice without command execution' do
      gogs_refused('legacy', { 'PASSWORD' => 'public-wrong-password' }, expected: 'Login failed')
    end
  elsif profile == 'gogs_rebase'
    it 'executes two ordinary-user own-repository commands with exact repository cleanup' do
      gogs_command('gogs')
    end

    it 'opens two ordinary-user own-repository Bash sessions and proves their target identity' do
      gogs_session('gogs', 'cmd/unix/reverse_bash')
    end

    it 'executes twice as an existing repository owner while enabling rebase' do
      gogs_command('gogs', { 'USERNAME' => 'lab-admin', 'ENABLE_REBASE' => true }, existing: true, rebase: false)
    end

    it 'opens two pre-enabled collaborator sessions despite zero repository creation quota' do
      gogs_session('gogs', 'cmd/unix/reverse_bash', options: { 'USERNAME' => 'lab-writer', 'ENABLE_REBASE' => false }, existing: true)
    end

    it 'refuses own repository creation twice for the native zero-quota writer' do
      gogs_refused('gogs', { 'USERNAME' => 'lab-writer' }, expected: 'Repo creation failed')
    end

    it 'refuses existing repository pushes twice for a native read-only collaborator' do
      gogs_refused('gogs', { 'USERNAME' => 'lab-reader', 'ENABLE_REBASE' => false }, existing: true, expected: 'failed')
    end

    it 'retains the actual disabled-rebase response and reporting without executing twice' do
      gogs_refused('gogs', { 'USERNAME' => 'lab-writer', 'ENABLE_REBASE' => false }, existing: true, rebase: false)
    end

    it 'refuses rejected API credentials twice before creating a repository' do
      gogs_refused('gogs', { 'PASSWORD' => 'public-wrong-password' }, expected: 'API token creation failed')
    end

    it 'executes two own-repository commands through an explicitly supplied real subpath' do
      gogs_command('prefix')
    end

    it 'refuses an inaccessible private existing repository twice for an outsider' do
      gogs_refused('gogs', { 'USERNAME' => 'lab-outsider', 'ENABLE_REBASE' => false }, existing: true, expected: 'not found or not accessible')
    end
  else
    it 'identifies the genuine fixed static asset version and reports its service' do
      expect(gogs_invoke('gogs', {}, action: 'check')).to include('The target is not exploitable', 'Gogs 0.14.3 detected, fixed in 0.14.3.')
      gogs_verify_reporting('gogs', exploited: false)
    end

    it 'refuses fixed-version AutoCheck twice before token or repository mutation' do
      gogs_refused('gogs', {}, expected: 'The target is not exploitable')
    end

    it 'delivers two genuine forced rebase attempts without execution on the fixed release' do
      gogs_refused('gogs', { 'ForceExploit' => true }, expected: 'Triggering rebase merge')
    end

    it 'does not identify the unrelated Apache root as vulnerable' do
      endpoint = target_runtime.fetch('module_endpoints').fetch('gateway')
      output = gogs_invoke('gogs', { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port') }, action: 'check')
      expect(output).to include('Target does not appear to be running Gogs.')
      expect(gogs_reporting.values).to eq([[], [], []])
    end

    it 'does not identify a missing application path as vulnerable' do
      # This must also expose the owner's actual TARGETURI option registration.
      expect(gogs_invoke('gogs', { 'TARGETURI' => '/module-target-absent/' }, action: 'check')).to include('Target does not appear to be running Gogs.')
      expect(gogs_reporting.values).to eq([[], [], []])
    end
  end
end
