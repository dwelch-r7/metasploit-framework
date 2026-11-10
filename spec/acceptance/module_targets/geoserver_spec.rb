require 'acceptance_spec_helper'
require 'base64'
require 'rex/parser/arguments'
require 'timeout'
require_relative '../../../test/module_targets/geoserver/acceptance_helpers'

profile = ENV.fetch('GEOSERVER_PROFILE', '2251')
raise ArgumentError, "Unknown GeoServer profile: #{profile}" unless %w[2251 2252 2256].include?(profile)

RSpec.describe 'Native GeoServer targets' do
  include_context 'module target'
  include_context 'wait_for_expect'
  prepend GeoServerAcceptance

  before(:all) do
    output, error, status = Open3.capture3('python3', '-B', 'test/module_targets/geoserver/native_probe.py')
    File.write(artifact('native-status.json'), JSON.pretty_generate(exitstatus: status.exitstatus, stderr: error))
    expect(status.success?).to be(true), error
    @native = JSON.parse(output)
    expect(@native.fetch('profile')).to eq(profile)
    expect(@native.fetch('version')).to eq({ '2251' => '2.25.1', '2252' => '2.25.2', '2256' => '2.25.6' }.fetch(profile))
    expect(@native.fetch('native_rce')).to eq(profile == '2251')
    expect(@native.fetch('native_xxe')).to eq(profile != '2256')
    target_runtime['module_endpoints'] = JSON.parse(File.read(artifact('native-endpoints.json'))).fetch('module_endpoints')
    output = console_command('irb -e \'load "test/module_targets/geoserver/input_audit.rb"; puts "GEOSERVER_CATALOG=" + GeoServerInputs.install(framework).to_json\'')
    expect(JSON.parse(output[/GEOSERVER_CATALOG=(\{.*\})/, 1])).to eq('target_name' => 'Unix Command', 'generic_compatible' => true)
    expect(returned_inputs).to eq([])
  end

  before do |example|
    @case_id = example.metadata.fetch(:scoped_id).tr(':', '_')
    expect(console_command('sessions -l')).to include('No active sessions')
    expect(console_command('jobs -l')).to include('No active jobs')
    @before_files = target_files
    @before_loot = loot_files
  end

  after do |example|
    if [Acceptance::ChildProcessRecvError, Acceptance::ChildProcessTimeoutError, EOFError, Errno::EPIPE].any? { |type| example.exception.is_a?(type) }
      @console_broken = true
      RSpec.world.wants_to_quit = true
    end
    if @before_files
      restore_files
      expect(target_exec('app', 'cat', @native.fetch('text_path'))).to eq(Base64.strict_decode64(@native.fetch('text_base64')))
      expect(target_exec('app', 'test', '!', '-s', @native.fetch('empty_path'))).to eq('')
      unless @console_broken
        begin
          expect(console_command('sessions -l')).to include('No active sessions')
          expect(console_command('jobs -l')).to include('No active jobs')
        ensure
          console_command('sessions -K')
          console_command('jobs -K')
        end
      end
    end
  end

  if profile == '2251'
    it 'reports hidden version, refuses default AutoCheck and executes a quiet override twice' do
      2.times do |iteration|
        expect_hidden_version
        prove_default_autocheck_refusal(iteration)
        prove_command('app', { 'AutoCheck' => false, 'ForceExploit' => false }, iteration, bytes: '')
      end
    end

    it 'executes an authenticated prefixed command twice using real Apache Basic policy' do
      2.times do |iteration|
        prove_command('gateway', { 'TARGETURI' => '/auth/', 'HttpUsername' => 'admin', 'HttpPassword' => 'geoserver', 'AutoCheck' => false }, iteration, bytes: "GeoServerProof#{iteration}")
      end
    end

    it 'rejects wrong frontend credentials twice without command proof or false loot' do
      2.times do |iteration|
        marker = "/tmp/module-target-geoserver-denied-#{@case_id}-#{iteration}"
        output = invoke(GeoServerAcceptance::RCE, 'gateway', generic_options("touch${IFS}#{marker}").merge('TARGETURI' => '/auth/', 'HttpUsername' => 'admin', 'HttpPassword' => 'wrong', 'AutoCheck' => false), allow_errors: true)
        expect(output).to include('No valid featuretype found')
        expect(@last_inputs).to include(hash_including('status' => 401))
        absent(marker)
        invoke(GeoServerAcceptance::XXE, 'gateway', { 'TARGETURI' => '/auth/geoserver', 'HttpUsername' => 'admin', 'HttpPassword' => 'wrong', 'FILEPATH' => @native.fetch('text_path') }, allow_errors: true)
        expect(@last_inputs).to include(hash_including('status' => 401))
        expect(loot_files).to eq(@before_loot)
      end
    end

    it 'reads exact ordinary text twice into separate local loot files' do
      read_file_twice
    end

    it 'returns no loot for missing and empty files on both repetitions' do
      absent('/tmp/module-target-geoserver-missing-input')
      read_file_twice(positive: false, path: '/tmp/module-target-geoserver-missing-input')
      read_file_twice(positive: false, path: @native.fetch('empty_path'))
    end

    it 'rejects unrelated genuine Apache twice without a false check or file read' do
      2.times do
        output = invoke(GeoServerAcceptance::RCE, 'unrelated', { 'TARGETURI' => '/unrelated/' }, action: 'check', allow_errors: true)
        expect(output).not_to include('The target appears to be vulnerable', 'The target is vulnerable')
      end
      read_file_twice('unrelated', { 'TARGETURI' => '/unrelated' }, positive: false)
    end
  else
    it 'reports hidden version, refuses default AutoCheck and rejects the fixed override twice' do
      2.times do |iteration|
        expect_hidden_version
        prove_default_autocheck_refusal(iteration)
        marker = "/tmp/module-target-geoserver-fixed-#{@case_id}-#{iteration}"
        output = invoke(GeoServerAcceptance::RCE, 'app', generic_options("touch${IFS}#{marker}").merge('AutoCheck' => false, 'ForceExploit' => false), allow_errors: true)
        expect(output).to include('No valid featuretype found')
        expect(@last_inputs).to include(hash_including('kind' => 'RETURNED-XML', 'arguments' => array_including('whoami')))
        absent(marker)
        expect(target_files).to eq(@before_files)
        expect(loot_files).to eq(@before_loot)
      end
    end

    it(profile == '2252' ? 'still reads exact XXE text twice after the RCE branch fix' : 'refuses XXE twice while ordinary native WMS remains functional') do
      read_file_twice(positive: profile == '2252')
    end
  end
end
