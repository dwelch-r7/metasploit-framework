require 'acceptance_spec_helper'
require 'base64'

RSpec.describe 'Linux post module targets' do
  include_context 'module target'
  include_context 'wait_for_expect'
  include_context 'native Linux session'

  let_it_be(:native_linux) do
    report = JSON.parse(target_exec('linux', 'python3', '/opt/native_probe.py'))
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-linux-preflight.json'), JSON.pretty_generate(report))
    expect(report.fetch('hostname')).to eq('module-target-linux-post')
    expect(report.fetch('uid')).to eq('0')
    expect(report.fetch('release')).to include('ID=ubuntu', 'VERSION_ID="22.04"')
    report
  end

  before(:all) { native_linux }

  {
    'shell' => { payload: 'linux/x64/shell_reverse_tcp', format: 'elf', file: 'shell-session.elf' },
    'meterpreter' => { payload: 'linux/x64/meterpreter_reverse_tcp', format: 'elf', file: 'meterpreter-session.elf' }
  }.each do |kind, delivery|
    context kind do
      let(:session_id) { open_native_session(kind, delivery) }

      after do
        console_command('sessions -K')
        console_command('jobs -K')
        target_exec('linux', 'rm', '-f', '/tmp/module-target-session-proof', '/tmp/shell-session.elf', '/tmp/meterpreter-session.elf')
      end

      it 'detects the actual Docker runtime' do
        output = run_target_module('post/linux/gather/checkcontainer', 'linux', { 'SESSION' => session_id })
        expect(output).to include("This appears to be a '#{native_linux.fetch('container')}' container", 'Post module execution completed')
      end

      it 'enumerates a native command from the normal paths' do
        output = run_target_module('post/linux/gather/enum_commands', 'linux', { 'SESSION' => session_id, 'DIR' => nil })
        expect(output).to include('/usr/bin/python3', '/bin/bash', 'Post module execution completed')
        expect(output).to match(%r{Found \d+ executable binaries/commands})
        expect(output).not_to include(native_linux.fetch('command'))
      end

      it 'handles the specialist directory and a missing directory on successive runs' do
        output = run_target_module('post/linux/gather/enum_commands', 'linux', { 'SESSION' => session_id, 'DIR' => '/opt/module-target-tools' })
        expect(output).to include(native_linux.fetch('command'), 'Post module execution completed')
        output = run_target_module('post/linux/gather/enum_commands', 'linux', { 'SESSION' => session_id, 'DIR' => '/opt/missing-module-target-directory' })
        expect(output).not_to include(native_linux.fetch('command'), '/opt/missing-module-target-directory/')
        expect(output).to include('/usr/bin/python3', 'Post module execution completed')
      end

      it 'saves the exact actual configuration files as loot' do
        output = run_target_module('post/linux/gather/enum_configs', 'linux', { 'SESSION' => session_id }, allow_errors: true)
        expect(output).to include('Post module execution completed')
        output.lines.select { |line| line.include?('[-]') }.each do |line|
          missing = line[%r{Failed to open file: (/[^:]+): core_channel_open: Operation failed: 1}, 1]
          expect(missing).not_to be_nil, line
          target_exec('linux', 'test', '!', '-e', missing)
        end
        native_linux.fetch('configs').each do |filename, encoded|
          basename = File.basename(filename)
          path = output[/#{Regexp.escape(basename)} stored in (.+)$/, 1]&.strip
          expect(path).not_to be_nil, output
          expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
          expect(File.binread(path)).to eq(Base64.strict_decode64(encoded))
        end
      end
    end
  end
end
