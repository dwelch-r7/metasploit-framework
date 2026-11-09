require 'acceptance_spec_helper'
require 'rbconfig'

RSpec.describe 'ZooKeeper through a native sliced stream' do
  include_context 'module target'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/zookeeper_segmented/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-sliced-zookeeper.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-sliced-zookeeper-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @native = JSON.parse(stdout)
  end

  it 'collects complete genuine environment and statistics twice through sliced TCP' do
    2.times do
      previous = Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')]
      output = run_target_module('auxiliary/gather/zookeeper_info_disclosure', 'sliced', { 'THREADS' => 1, 'TIMEOUT' => 5 })
      paths = output.scan(/File saved in: (.+)$/).flatten.map(&:strip)
      expect(paths.length).to eq(2)
      expect(paths.sort).to eq((Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')] - previous).sort)
      contents = paths.map do |path|
        expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
        File.binread(path)
      end
      environment = contents.find { |data| data.start_with?("Environment:\n") }
      expect(environment).not_to be_nil
      fields = environment.lines.filter_map { |line| line.strip.split('=', 2) if line.include?('=') }.to_h
      expect(fields.keys).to match_array(@native.fetch('environment').keys)
      expect(fields.except('os.memory.free', 'os.memory.total')).to eq(@native.fetch('environment').except('os.memory.free', 'os.memory.total'))
      statistics = contents.find { |data| data.start_with?('Zookeeper version:') }
      expect(statistics).not_to be_nil
      expect(statistics).to include("Zookeeper version: #{@native.fetch('environment').fetch('zookeeper.version')}\n", "Mode: standalone\n")
    end
  end
end
