# frozen_string_literal: true

require 'json'
require 'time'
require 'msf/core/exploit/retry'

# Passive events are emitted only after the real Framework session bootstrap.
class DruidSessionObserver
  include Msf::SessionEvent

  def initialize(path)
    @path = path
  end

  def on_session_open(session)
    row = { id: session.sid, type: session.type, peer: session.tunnel_peer, at: Time.now.utc.iso8601 }
    File.open(@path, 'a') { |output| output.puts(JSON.generate(row)) }
  end
end

# Uses the public session API for remote proof and graceful remote shutdown.
module DruidSessionControl
  extend Msf::Exploit::Retry

  PROOF_TIMEOUT = 5

  def self.install(framework)
    path = File.join(File.dirname(Msf::Config.config_directory), 'ready-sessions.jsonl')
    File.write(path, '')
    framework.events.add_session_subscriber(DruidSessionObserver.new(path))
    { installed: true, ready_event_path: path }
  end

  def self.proof(framework, identifier, path)
    raise ArgumentError, 'Unexpected proof path' unless path.match?(%r{\A/tmp/module-target-druid-session-[0-9_]+-[0-9]+\z})

    session = framework.sessions.fetch(identifier)
    if session.type == 'meterpreter'
      pid = session.sys.process.getpid
      identity = session.sys.config.getuid
      proof_process = touch_proof(session, path)
      { id: identifier, type: session.type, pid: pid, identity: identity, command: "/bin/touch #{path}", expected: '', proof_process: proof_process }
    elsif session.type == 'shell'
      command = "printf %s druid-session > #{path}; id; echo $$"
      output = session.shell_command_token(command)
      pid = output.to_s.lines.map(&:strip).reverse.find { |line| line.match?(/\A\d+\z/) }
      raise "Remote shell did not return a PID: #{output.inspect}" unless pid

      { id: identifier, type: session.type, pid: pid.to_i, identity: output, command: command, expected: 'druid-session' }
    else
      raise ArgumentError, "Unsupported real session type: #{session.type}"
    end
  end

  def self.touch_proof(session, path)
    process = session.sys.process.execute('/bin/touch', path, 'Hidden' => true, 'Channelized' => false)
    evidence = { pid: process.pid, file_observed: false }
    begin
      # Mettle's process.close sends SIGINT, so RPC acceptance must not be
      # followed by close before touch has created its file. Callers still
      # independently verify the physical file, bytes and owning UID.
      observed = poll_until_truthy(timeout: PROOF_TIMEOUT, interval: 0.1) do
        stat = session.fs.file.stat(path)
        stat.file? && stat.size.zero? # rubocop:disable Style/ZeroLengthPredicate -- Remote FileStat does not implement empty?.
      rescue Rex::Post::Meterpreter::RequestError => e
        # Meterpreters differ in their missing-file error codes (PHP uses a
        # generic failure). Retain the diagnostic if no valid stat arrives.
        evidence[:stat_error] = e.message
        false
      end
      evidence[:file_observed] = observed || false
    ensure
      process.close
      evidence[:close_requested] = true
      # Process.close does not wait for the remote response. Verify that the
      # child is gone, including on timeout or an observation failure.
      absent = poll_until_truthy(timeout: PROOF_TIMEOUT, interval: 0.1) do
        session.sys.process.get_processes.none? { |entry| entry['pid'] == evidence[:pid] }
      end
      evidence[:cleanup] = absent ? 'child_absent' : 'child_still_present'
      raise IOError, "Unable to clean up proof child #{evidence[:pid]}: #{evidence.to_json}" unless absent
    end
    raise IOError, "Remote touch proof was not established: #{evidence.to_json}" unless evidence[:file_observed]

    evidence
  end

  def self.exit_remote(framework, identifier)
    session = framework.sessions.fetch(identifier)
    if session.type == 'meterpreter'
      session.core.shutdown
    elsif session.type == 'shell'
      session.shell_write("exit\n")
    else
      raise ArgumentError, "Unsupported real session type: #{session.type}"
    end
    { id: identifier, graceful_remote_exit_requested: true }
  end

  def self.dispatch(framework, action, identifier = nil, path = nil)
    case action
    when 'proof'
      proof(framework, identifier, path)
    when 'exit'
      exit_remote(framework, identifier)
    when 'snapshot'
      framework.sessions.map { |index, session| { id: index, type: session.type } }
    else
      raise ArgumentError, "Unknown session action: #{action}"
    end
  rescue StandardError => e
    { error: e.class.name, message: e.message }
  end
end
