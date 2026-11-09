require 'acceptance_spec_helper'
require 'base64'

RSpec.describe 'Linux system collection targets' do
  include_context 'module target'
  include_context 'wait_for_expect'
  include_context 'native Linux session'

  let_it_be(:native_users) do
    %w[root labuser].to_h do |user|
      report = JSON.parse(target_exec('linux', 'runuser', '-u', user, '--', 'python3', '/opt/system-native-probe.py'))
      expect(report.fetch('username')).to eq(user)
      expect(report.fetch('uid')).to eq(user == 'root' ? '0' : '1000')
      expect(report.fetch('hostname')).to eq('module-target-linux-system')
      File.write(File.join(target_runtime.fetch('artifacts'), "native-#{user}-preflight.json"), JSON.pretty_generate(report))
      [user, report]
    end
  end

  before(:all) { native_users }

  %w[root labuser].each do |user|
    {
      'shell' => { payload: 'linux/x64/shell_reverse_tcp', format: 'elf', file: 'shell-session.elf' },
      'meterpreter' => { payload: 'linux/x64/meterpreter_reverse_tcp', format: 'elf', file: 'meterpreter-session.elf' }
    }.each do |kind, delivery|
      context "#{user} #{kind}" do
        let(:session_id) { open_native_session(kind, delivery, user: user) }
        let(:native) { native_users.fetch(user) }

        after do
          console_command('sessions -K')
          console_command('jobs -K')
          target_exec('linux', 'rm', '-f', '/tmp/module-target-session-proof', '/tmp/shell-session.elf', '/tmp/meterpreter-session.elf')
        end

        it 'collects actual user, package and cron data' do
          output = run_target_module('post/linux/gather/enum_system', 'linux', { 'SESSION' => session_id }, allow_errors: true, endpoint_options: {}, command_timeout: 180)
          verify_collection_errors(output, user)
          expect(output).to include('Post module execution completed', native.fetch('kernel'))
          accounts = loot_body(output, 'User accounts')
          names = Base64.strict_decode64(native.fetch('files').fetch('/etc/passwd')).lines.map { |line| line.split(':', 2).first }
          expect(accounts.strip).to eq(names.join("\n"))
          expect(loot_body(output, 'Installed Packages').strip).to eq(Base64.strict_decode64(native.fetch('packages')).strip)
          cron = loot_body(output, 'Cron jobs')
          expect(cron).to include(Base64.strict_decode64(native.fetch('cron')).strip)
          if user == 'root'
            expect(cron).to include(Base64.strict_decode64(native_users.fetch('labuser').fetch('cron')).strip)
          else
            expect(cron).not_to include('module-target-root-cron')
          end
        end

        it 'collects actual network, configuration and owned SSH key data' do
          output = run_target_module('post/linux/gather/enum_network', 'linux', { 'SESSION' => session_id }, allow_errors: true, endpoint_options: {}, command_timeout: 180)
          verify_collection_errors(output, user)
          expect(output).to include('Post module execution completed')
          %w[DNS\ config Host\ file SSHD\ config].zip(%w[/etc/resolv.conf /etc/hosts /etc/ssh/sshd_config]).each do |label, filename|
            expect(loot_body(output, label)).to eq(Base64.strict_decode64(native.fetch('files').fetch(filename)))
          end
          interfaces = loot_body(output, 'Network config')
          native.fetch('network').each do |interface|
            expect(interfaces).to include(interface.fetch('ifname'))
            interface.fetch('addr_info', []).each { |address| expect(interfaces).to include(address.fetch('local')) }
          end
          expect(loot_body(output, 'Listening ports')).to include(':8080')
          keys = loot_body(output, 'SSH keys')
          private_key = Base64.strict_decode64(native.fetch('files').fetch('/home/labuser/.ssh/id_ed25519'))
          public_key = Base64.strict_decode64(native.fetch('files').fetch('/home/labuser/.ssh/id_ed25519.pub'))
          expect(keys).to include(private_key.lines.fetch(1).strip, public_key.strip)
          if user == 'root'
            expect(loot_body(output, 'Firewall config')).to include('module-target-firewall-proof')
          else
            expect(output).to include('Unable to get data for Firewall config')
          end
        end

        it 'reports actual kernel settings and the installed firewall application' do
          output = run_target_module('post/linux/gather/enum_protections', 'linux', { 'SESSION' => session_id }, allow_errors: true, endpoint_options: {}, command_timeout: 180)
          verify_collection_errors(output, user)
          expect(output).to include('Post module execution completed', native.fetch('kernel'), 'iptables found:')
          {
            'aslr' => ['ASLR is enabled', %w[1 2]],
            'kptr' => ['Kernel pointer restriction is enabled', %w[1 2]],
            'dmesg' => ['dmesg restriction is enabled', ['1']]
          }.each do |setting, (message, enabled)|
            if enabled.include?(native.fetch('protections').fetch(setting))
              expect(output).to include(message)
            else
              expect(output).not_to include(message)
            end
          end
        end
      end
    end
  end

  def loot_body(output, label)
    path = output[/#{Regexp.escape(label)} stored in (.+)$/, 1]&.strip
    expect(path).not_to be_nil, output
    expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
    File.binread(path)
  end

  def verify_collection_errors(output, user)
    output.lines.select { |line| line.include?('[-]') }.each do |line|
      next if user == 'labuser' && line.strip == '[-] Unable to get data for Firewall config'

      missing = line[%r{Failed to open file: (/[^:]+): core_channel_open: Operation failed: 1}, 1]
      expect(missing).not_to be_nil, line
      target_exec('linux', 'test', '!', '-e', missing)
    end
  end
end
