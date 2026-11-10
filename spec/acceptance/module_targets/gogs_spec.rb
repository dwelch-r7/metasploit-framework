require 'acceptance_spec_helper'
require 'nokogiri'
require 'uri'

profile = ENV.fetch('GOGS_TARGET_PROFILE', 'gogs_hooks')
raise ArgumentError, "Unknown Gogs profile: #{profile}" unless %w[gogs_hooks gogs_rebase gogs_rebase_fixed].include?(profile)

group = ENV.fetch('GOGS_REBASE_GROUP', 'all')
raise ArgumentError, "Unknown Gogs rebase group: #{group}" unless %w[all own existing].include?(group)

if profile == 'gogs_rebase' && group != 'all'
  RSpec.configure { |config| config.filter_run_excluding(gogs_rebase_group: group == 'own' ? :existing : :own) }
end

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
    it 'executes two ordinary-user own-repository commands with exact repository cleanup', gogs_rebase_group: :own do
      gogs_command('gogs')
    end

    it 'opens two ordinary-user own-repository Bash sessions and proves their target identity', gogs_rebase_group: :own do
      gogs_session('gogs', 'cmd/unix/reverse_bash')
    end

    it 'executes twice as an existing repository owner while enabling rebase', gogs_rebase_group: :existing do
      gogs_command('gogs', { 'USERNAME' => 'lab-admin', 'ENABLE_REBASE' => true }, existing: true, rebase: false)
    end

    it 'opens two pre-enabled collaborator sessions despite zero repository creation quota', gogs_rebase_group: :existing do
      gogs_session('gogs', 'cmd/unix/reverse_bash', options: { 'USERNAME' => 'lab-writer', 'ENABLE_REBASE' => false }, existing: true)
    end

    it 'refuses own repository creation twice for the native zero-quota writer', gogs_rebase_group: :own do
      gogs_refused('gogs', { 'USERNAME' => 'lab-writer' }, expected: 'Repo creation failed')
    end

    it 'refuses existing repository pushes twice for a native read-only collaborator', gogs_rebase_group: :existing do
      gogs_refused('gogs', { 'USERNAME' => 'lab-reader', 'ENABLE_REBASE' => false }, existing: true, expected: 'failed')
    end

    it 'retains the actual disabled-rebase response and reporting without executing twice', gogs_rebase_group: :existing do
      gogs_refused('gogs', { 'USERNAME' => 'lab-writer', 'ENABLE_REBASE' => false }, existing: true, rebase: false)
    end

    it 'refuses rejected API credentials twice before creating a repository', gogs_rebase_group: :own do
      gogs_refused('gogs', { 'PASSWORD' => 'public-wrong-password' }, expected: 'API token creation failed')
    end

    it 'executes two own-repository commands through an explicitly supplied real subpath', gogs_rebase_group: :own do
      gogs_command('prefix')
    end

    it 'refuses an inaccessible private existing repository twice for an outsider', gogs_rebase_group: :existing do
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
      route = '/module-target-absent/'
      native = gogs_native(action: 'http', service: 'gogs', route: route)
      artifacts = target_runtime.fetch('artifacts')
      response = JSON.parse(File.readlines(File.join(artifacts, 'native-gogs-http.jsonl')).last)
      body = Base64.strict_decode64(response.fetch('body_base64'))
      File.write(File.join(artifacts, 'native-fixed-missing-path.json'), JSON.pretty_generate(response: response, body_sha256: Digest::SHA256.hexdigest(body)))
      expect(response.values_at('service', 'method', 'status')).to eq(['gogs', 'GET', 404])
      expect(URI.parse(response.fetch('url')).path).to eq(route)
      expect(URI.parse(response.fetch('url')).query).to be_nil
      expect(native.fetch('status')).to eq(404)
      expect(native.fetch('document')).to be_a(String)
      expect(body).to eq(native.fetch('document').b)
      identity = JSON.parse(File.read(File.join(artifacts, 'native-gogs-probe.json'))).fetch('identities').fetch('gogs')
      expect(identity.fetch('version')).to eq('Gogs version 0.14.3')
      html = Nokogiri::HTML(body)
      expect(html.css('meta[name="author"]').map { |node| node['content'] }).to eq(['Gogs'])
      # The full native gate already verifies this hash against the tagged release.
      expect(html.css('link[rel="stylesheet"]').map { |node| node['href'] }).to include("/css/gogs.min.css?v=#{identity.fetch('asset_hash')}")
      output = gogs_invoke('gogs', { 'TARGETURI' => route }, action: 'check')
      expect(output).to include("GET #{route} HTTP/1.1", 'HTTP/1.1 404 Not Found', 'The target is not exploitable', 'Gogs 0.14.3 detected, fixed in 0.14.3.')
      report = gogs_verify_reporting('gogs', exploited: false)
      expect(report.fetch(:services).find { |row| row.fetch('name') == 'gogs' }.fetch('info')).to eq('Gogs Git Service 0.14.3')
      expect(gogs_reporting_provenance).to eq(references: [], sessions: [], attempts: [], checks: [])
    end
  end
end
