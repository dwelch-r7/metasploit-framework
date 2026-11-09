require 'acceptance_spec_helper'
require 'rbconfig'

RSpec.describe 'Native ZooKeeper information targets' do
  include_context 'module target'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/zookeeper/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-zookeeper.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-zookeeper-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @native = JSON.parse(stdout)
  end

  %w[legacy modern environment_only statistics_only restricted].each do |service|
    it "collects permitted genuine #{service} information twice" do
      2.times { verify_collection(service, scan(service, allow_errors: service.end_with?('only') || service == 'restricted')) }
    end
  end

  it 'uses the documented default timeout when TIMEOUT is zero' do
    output = scan('modern', { 'TIMEOUT' => 0 })
    expect(output).to include('Using a timeout of 30...')
    verify_collection('modern', output)
  end

  it 'collects actual information with an explicit short timeout' do
    output = scan('modern', { 'TIMEOUT' => 1 })
    expect(output).to include('Using a timeout of 1...')
    verify_collection('modern', output)
  end

  it 'does not identify unrelated actual Apache as ZooKeeper or store its content' do
    previous = loot_files
    output = scan('unrelated', {}, allow_errors: true)
    expect(output).not_to include('Service looks fine', 'File saved in:')
    expect(loot_files).to eq(previous)
  end

  def scan(service, options = {}, allow_errors: false)
    @previous_loot = loot_files
    run_target_module('auxiliary/gather/zookeeper_info_disclosure', service, { 'THREADS' => 1, 'TIMEOUT' => 2 }.merge(options), allow_errors: allow_errors)
  end

  def verify_collection(service, output)
    profile = @native.fetch('profiles').fetch(service)
    paths = output.scan(/File saved in: (.+)$/).flatten.map(&:strip)
    expect(paths.sort).to eq((loot_files - @previous_loot).sort)
    expected_count = %w[envi stat].count { |command| profile.fetch('allowed').include?(command) }
    expect(paths.length).to eq(expected_count), output
    contents = paths.map do |path|
      expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
      File.binread(path)
    end
    if profile.fetch('allowed').include?('envi')
      environment = contents.find { |text| text.start_with?("Environment:\n") }
      expect(environment).not_to be_nil
      fields = environment.lines.filter_map { |line| line.strip.split('=', 2) if line.include?('=') }.to_h
      expect(fields.keys).to match_array(profile.fetch('environment').keys)
      stable = profile.fetch('environment').except('os.memory.free', 'os.memory.total')
      expect(fields.except('os.memory.free', 'os.memory.total')).to eq(stable)
      %w[os.memory.free os.memory.total].each do |field|
        expect(fields.fetch(field)).to match(/\A\d+MB\z/) if profile.fetch('environment').key?(field)
      end
      if profile.fetch('environment').key?('os.memory.free')
        expect(fields.fetch('os.memory.free').to_i).to be <= fields.fetch('os.memory.total').to_i
        expect(fields.fetch('os.memory.total').to_i).to be <= fields.fetch('os.memory.max').to_i
      end
      expect(output).to include("zookeeper.version=#{profile.fetch('cli_version')}")
    else
      expect(output).to include('Server does not allow accessing environment information.')
    end
    if profile.fetch('allowed').include?('stat')
      statistics = contents.find { |text| text.start_with?('Zookeeper version:') }
      expect(statistics).not_to be_nil
      expect(statistics).to include("Zookeeper version: #{profile.fetch('cli_version')}\n", "Mode: standalone\n")
      expect(statistics[/^Node count: (\d+)$/, 1]).to eq(profile.fetch('responses').fetch('stat')[/^Node count: (\d+)$/, 1])
      expect(statistics).to match(%r{^Latency min/avg/max: \d+/\d+(?:\.\d+)?/\d+$})
    else
      expect(output).to include('Server does not allow accessing statistics.')
    end
  end

  def loot_files
    Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')]
  end
end
