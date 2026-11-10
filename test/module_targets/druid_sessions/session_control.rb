# frozen_string_literal: true

require 'json'
require 'time'

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
      process = session.sys.process.execute('/bin/touch', path, 'Hidden' => true, 'Channelized' => false)
      process.close
      { id: identifier, type: session.type, pid: pid, identity: identity, command: "/bin/touch #{path}", expected: '' }
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
