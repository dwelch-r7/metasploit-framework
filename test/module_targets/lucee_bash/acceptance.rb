# frozen_string_literal: true

require_relative '../laravel/sessions'
require_relative '../lucee/acceptance'

# Calibrate the stock shell independently, then verify normal owner cleanup.
module LuceeSessions
  include LaravelSessions
  include LuceeTarget

  FAMILIES = { 'bash-shell' => [0, 'cmd/unix/reverse_bash', 'shell'] }.freeze

  def laravel_uid
    0
  end

  def session_families
    FAMILIES
  end

  def session_default_options
    { 'bash-shell' => %w[TARGET PAYLOAD] }
  end

  def session_control_name
    'LuceeSessionControl'
  end

  def session_health_path
    '/module-target-native.cfm'
  end

  def process_state
    output, = rc_command('process-state', 'target', 'perl', '/opt/module-target-process-state.pl', LaravelSessions::CALLBACK_PORT.to_s)
    raw = JSON.parse(output)
    processes = raw.fetch('processes').map do |row|
      row.except('starttime', 'cmdline').merge('birth' => row.fetch('starttime'), 'command' => row.fetch('cmdline').strip, 'uid' => row.fetch('uid').to_s)
    end
    processes.reject! do |row|
      row.fetch('command') == session_health_command || row.values_at('uid', 'ppid', 'command') == ['0', 0, 'runc init']
    end
    { 'processes' => processes, 'connections' => raw.fetch('connections').reject { |row| row.fetch('state') == '06' } }
  end

  def callback_control
    server = TCPServer.new('0.0.0.0', LaravelSessions::CALLBACK_PORT)
    token = 'lucee-' + Rex::Text.rand_text_alphanumeric(24)
    program = <<~'PERL'
      use strict;
      use warnings;
      use JSON::PP;
      use IO::Socket::INET;
      use Socket qw(inet_ntoa);
      my ($token, $port) = @ARGV;
      my $host = inet_ntoa((gethostbyname('host.docker.internal'))[4]);
      my $identity = { host => $host, token => $token, uid => 0 + $>, pid => 0 + $$, ppid => 0 + getppid() };
      my $json = JSON::PP->new->canonical->encode($identity);
      my $peer = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => 'tcp', Timeout => 8) or die "Cannot connect native callback: $!";
      $peer->autoflush(1);
      print $peer $json, "\n";
      my $answer = <$peer>;
      die "Native callback acknowledgment mismatch" unless defined($answer) && $answer eq "ACK:$token\n";
      close $peer;
      print $json, "\n";
    PERL
    task = Thread.new { Open3.capture3(*session_exec_argv('perl', '-e', program, token, LaravelSessions::CALLBACK_PORT.to_s)) }
    task.report_on_exception = false
    raise Timeout::Error, 'No native Lucee callback' unless IO.select([server], nil, nil, 8)

    peer = server.accept
    identity = JSON.parse(Timeout.timeout(5) { peer.gets })
    expect(identity).to include('token' => token, 'uid' => laravel_uid)
    state = process_state
    process = state.fetch('processes').find { |row| row.fetch('pid') == identity.fetch('pid') }
    expect(process).to include('uid' => laravel_uid.to_s, 'ppid' => identity.fetch('ppid'), 'birth' => be_a(String))
    connected = state.fetch('connections').select { |row| row.fetch('state') == '01' }.map { |row| row.fetch('inode') }
    expect(connected & process.fetch('connection_inodes')).not_to be_empty
    @rc[:callback] = { identity: identity, observed: state }
    peer.puts('ACK:' + token)
    peer.close
    output, error, status = Timeout.timeout(15) { task.value }
    @rc[:callback].merge!(stdout: output, stderr: error, exit: status.exitstatus)
    expect(status.success?).to be(true), output + error
    expect(JSON.parse(output)).to eq(identity)
    @listener_host = identity.fetch('host')
    settled
  ensure
    peer&.close unless peer&.closed?
    server&.close
    task&.join(15)
    rc_save
  end

  def use_session(family, attempt, owner)
    metadata = await_session(session_families.fetch(family)[1], owner)
    expect(rc_json('framework.sessions.keys')).to eq([metadata.fetch('id')])
    if owner == laravel_owner
      attempt[:effective_selection] = rc_json('{raw_target:active_module.datastore["TARGET"],target:active_module.target_index,payload:active_module.datastore["PAYLOAD"],allow_no_cleanup:active_module.datastore["AllowNoCleanup"]}')
      expect(attempt.fetch(:effective_selection)).to include('target' => 0, 'payload' => 'cmd/unix/reverse_bash', 'allow_no_cleanup' => be_falsey)
      lifecycle = rc_poll(15) do
        values = rc_json('framework.instance_variable_get(:@lucee_lifecycle_events)')
        values if values.any? { |row| row['event'] == 'return' && row['method'] == 'on_new_session' && row['session'] == metadata.fetch('id') }
      end
      current = lifecycle.drop(@rc.fetch(:lifecycle_cursor, 0))
      @rc[:lifecycle_cursor] = lifecycle.length
      events = rc_json('framework.instance_variable_get(:@lucee_events)').drop(@rc.fetch(:event_cursor, 0))
      @rc[:event_cursor] = rc_json('framework.instance_variable_get(:@lucee_events).length')
      positive = current.find { |row| row['event'] == 'return' && row['method'] == 'write_cfml_stub' }
      cleaned = current.find { |row| row['event'] == 'return' && row['method'] == 'on_new_session' }
      attempt[:events] = events
      attempt[:lifecycle] = current
      rc_save
      expect(positive).not_to be_nil
      expect(positive.fetch('allow_no_cleanup')).to be_falsey
      physical = positive.fetch('physical')
      write = events.find { |row| row['event'] == 'call' && row['method'] == 'write_file' && row['name'].end_with?('.cfm') }
      expect(write).not_to be_nil
      expect(physical).to include('exists' => true)
      expect(physical.fetch('content')).to include('exit' => 0, 'stdout_base64' => Base64.strict_encode64(Base64.strict_decode64(write.fetch('contents_base64')) + "\n"))
      expect(physical.fetch('uid')).to include('exit' => 0, 'stdout_base64' => Base64.strict_encode64("0\n"))
      expect(positive.fetch('directory').fetch('exit')).to eq(0)
      expect(cleaned.fetch('session')).to eq(metadata.fetch('id'))
      expect(cleaned.values_at('dropped_files', 'dropped_dirs')).to eq([[], []])
      expect(cleaned.fetch('physical')).to include('exists' => false)
      expect(cleaned.fetch('directory').fetch('exit')).to eq(1)
      expect(file(physical.fetch('path'))).to eq('exists' => false)
      expect(current.select { |row| row['event'] == 'return' && row['method'] == 'file_dropper_delete_file' }.length).to eq(1)
      expect(current.select { |row| row['event'] == 'return' && row['method'] == 'file_dropper_delete_dir' }.length).to eq(1)
      attempt[:automatic_cleanup_before_fixture] = true
    end
    result = super
    state = attempt.fetch(:live_state)
    process = state.fetch('processes').find { |row| row.fetch('pid') == attempt.fetch(:proof).fetch('pid') }
    connections = state.fetch('connections').select { |row| row.fetch('state') == '01' }
    expect(connections.length).to eq(1)
    expect(process.fetch('connection_inodes')).to include(connections.first.fetch('inode'))
    expect(attempt.fetch(:open_reports).select { |row| row['closed_at'].nil? }.map { |row| row.fetch('id') }).to eq([metadata.fetch('db_id')])
    attempt[:single_session_socket_and_open_report] = true
    result
  ensure
    rc_save
  end
end
