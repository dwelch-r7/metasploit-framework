require 'acceptance_spec_helper'
require 'rbconfig'

RSpec.describe 'Genuine Grafana traversal boundaries' do
  include_context 'module target'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/grafana_traversal/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-grafana.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-grafana-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @profiles = JSON.parse(stdout).fetch('profiles')
    @proof = File.binread('test/module_targets/grafana_traversal/proof.txt')
  end

  %w[v806 v807 v817 v818 v826 v827 v830 v831 prefix].each do |service|
    it "checks the genuine #{service} version against independently verified traversal" do
      profile = @profiles.fetch(service)
      output = invoke(service, action: 'check', allow_errors: !profile.fetch('vulnerable'))
      expect(output).to include(profile.fetch('version'))
      if profile.fetch('vulnerable')
        expect(output).to include('The target appears to be vulnerable')
      else
        expect(output).to include('The target is not exploitable')
        expect(output).not_to include('Detected vulnerable Grafana:')
      end
    end

    it "collects only actual permitted #{service} file bytes twice" do
      2.times do
        previous = loot_files
        profile = @profiles.fetch(service)
        output = invoke(service, allow_errors: !profile.fetch('vulnerable'))
        paths = output.scan(/File saved in: (.+)$/).flatten.map(&:strip)
        expected_count = @profiles.fetch(service).fetch('vulnerable') ? 1 : 0
        expect(paths.length).to eq(expected_count), output
        expect(paths.sort).to eq((loot_files - previous).sort)
        unless profile.fetch('vulnerable')
          refusal = "Detected non-vulnerable Grafana: #{profile.fetch('version')}"
          expect(output).to include(refusal)
          expect(output.lines.grep(/\[-\]/)).to all(include(refusal))
        end
        paths.each do |path|
          expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
          expect(File.binread(path)).to eq(@proof)
        end
      end
    end
  end

  {
    'missing plugin' => { 'PLUGINS_FILE' => 'missing-plugins.txt' },
    'missing file' => { 'FILEPATH' => '/etc/grafana/module-target-file-does-not-exist' },
    'insufficient depth' => { 'DEPTH' => 0 }
  }.each do |label, options|
    it "does not store loot for native #{label}" do
      previous = loot_files
      output = invoke('v830', options)
      expect(output).not_to include('File saved in:', 'exploited successfully')
      expect(loot_files).to eq(previous)
    end
  end

  it 'does not identify ordinary Apache as vulnerable Grafana' do
    output = invoke('unrelated', action: 'check', allow_errors: true)
    expect(output).not_to include('The target appears to be vulnerable', 'Detected vulnerable Grafana:')
  end

  it 'does not collect ordinary Apache content as Grafana loot' do
    previous = loot_files
    output = invoke('unrelated', allow_errors: true)
    expect(output).not_to include('File saved in:', 'exploited successfully')
    expect(loot_files).to eq(previous)
  end

  def invoke(service, options = {}, action: 'run', allow_errors: false)
    target_uri = service == 'prefix' ? '/observability/' : '/'
    defaults = {
      'TARGETURI' => target_uri, 'THREADS' => 1,
      'FILEPATH' => '/etc/grafana/module-target-proof.txt', 'DEPTH' => 13,
      'PLUGINS_FILE' => 'plugins.txt'
    }
    values = defaults.merge(options)
    values['PLUGINS_FILE'] = File.join('/usr/src/metasploit-framework/test/module_targets/grafana_traversal', values.fetch('PLUGINS_FILE'))
    run_target_module('auxiliary/scanner/http/grafana_plugin_traversal', service, values, action: action, allow_errors: allow_errors)
  end

  def loot_files
    Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')]
  end
end
