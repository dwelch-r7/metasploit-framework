require 'acceptance_spec_helper'
require 'base64'

RSpec.describe 'Ansible controller collection targets' do
  include_context 'module target'
  include_context 'wait_for_expect'
  include_context 'native Linux session'

  let_it_be(:native_users) do
    %w[root labuser].to_h do |user|
      report = JSON.parse(target_exec('linux', 'runuser', '-u', user, '--', 'python3', '/opt/ansible-native-probe.py'))
      expect(report.fetch('username')).to eq(user)
      expect(report.fetch('uid')).to eq(user == 'root' ? 0 : 1000)
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
          target_exec('linux', 'rm', '-f', '/tmp/module-target-session-proof', '/tmp/shell-session.elf', '/tmp/meterpreter-session.elf')
        end

        it 'collects genuine inventory, successful/rejected ping states, config and key' do
          output = gather
          aggregate_failures do
            verify_inventory(output, native.fetch('inventory'))
            verify_ping(output, rejected: true)
            verify_config(output, '/etc/ansible/ansible.cfg')
            expect(loot_bytes(output, 'Stored private key file to:')).to eq(native_bytes('/etc/ansible/id_ed25519'))
          end
        end

        it 'restricts pings to the selected host group while retaining full inventory' do
          output = gather({ 'HOSTS' => 'reachable' })
          aggregate_failures do
            verify_inventory(output, native.fetch('inventory'))
            verify_ping(output, rejected: false)
          end
        end

        if user == 'root'
          it 'collects a valid compact INI configuration and its exact key bytes' do
            output = gather({ 'ANSIBLECFG' => '/etc/ansible/compact.cfg' })
            verify_config(output, '/etc/ansible/compact.cfg')
            expect(loot_bytes(output, 'Stored private key file to:')).to eq(native_bytes('/etc/ansible/id_ed25519'))
          end

          it 'handles an actually empty inventory without false host records' do
            original_session = session_id
            target_exec('linux', 'cp', '/etc/ansible/hosts', '/etc/ansible/hosts.native-backup')
            begin
              target_exec('linux', 'python3', '-c', 'from pathlib import Path; Path("/etc/ansible/hosts").write_text("")')
              empty = JSON.parse(target_exec('linux', '/usr/bin/ansible-inventory', '--list'))
              expect(empty.fetch('_meta').fetch('hostvars')).to eq({})
              output = gather({ 'SESSION' => original_session })
              verify_inventory(output, empty)
              expect(output).not_to include('Ansible Hosts', 'Ansible Pings', 'module_node', 'module_denied')
              verify_config(output, '/etc/ansible/ansible.cfg')
            ensure
              target_exec('linux', 'mv', '/etc/ansible/hosts.native-backup', '/etc/ansible/hosts')
            end
          end
        else
          it 'retains readable configuration and handles the natively denied private key' do
            output = gather({ 'ANSIBLECFG' => '/etc/ansible/protected.cfg' }, allow_errors: true)
            verify_config(output, '/etc/ansible/protected.cfg')
            expect(output).not_to include('Stored private key file to:')
            expect(output).to match(%r{(?:Unable to read|not readable).*?/etc/ansible/root_only_key})
          end
        end
      end
    end
  end

  def gather(options = {}, allow_errors: false)
    run_target_module('post/linux/gather/ansible', 'linux', {
      'SESSION' => session_id, 'ANSIBLE' => '/usr/bin/ansible',
      'ANSIBLEINVENTORY' => '/usr/bin/ansible-inventory', 'HOSTS' => 'all'
    }.merge(options), allow_errors: allow_errors, endpoint_options: {}, command_timeout: 90)
  end

  def native_bytes(path)
    Base64.strict_decode64(native.fetch('files').fetch(path).fetch('data'))
  end

  def loot_bytes(output, label)
    path = output[/#{Regexp.escape(label)} (.+)$/, 1]&.strip
    expect(path).not_to be_nil, output
    return unless path

    expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
    File.binread(path)
  end

  def verify_inventory(output, expected)
    inventory = nil
    expect { inventory = JSON.parse(loot_bytes(output, 'Stored inventory to:')) }.not_to raise_error
    expect(inventory).to eq(expected)
  end

  def verify_config(output, path)
    expect(loot_bytes(output, 'Stored config to:')).to eq(native_bytes(path))
  end

  def verify_ping(output, rejected:)
    table = output.split('Ansible Pings', 2).last.to_s.split('Stored config to:', 2).first
    expect(table).to match(/^\s+module_node\s+SUCCESS\s+pong\s+false\s*$/)
    if rejected
      expect(table).to match(/^\s+module_denied\s+UNREACHABLE!\s*$/)
    else
      expect(table).not_to include('module_denied')
    end
  end
end
