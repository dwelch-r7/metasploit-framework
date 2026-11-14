# frozen_string_literal: true

require_relative '../druid_sessions/session_control'

# Reuse the real session-open observer and public session APIs for remote proof.
module MCPJamSessionControl
  def self.install(framework)
    DruidSessionControl.install(framework)
  end

  def self.proof(framework, identifier, path, marker)
    raise ArgumentError, 'Invalid controlled proof path' unless path.match?(%r{\A/tmp/module-target-mcpjam-session-[0-9_]+-[0-9]+\z})
    raise ArgumentError, 'Invalid controlled marker' unless marker.match?(/\A[a-z0-9_-]+\z/)

    session = framework.sessions.fetch(identifier)
    if session.type == 'meterpreter'
      pid = session.sys.process.getpid
      identity = session.sys.config.getuid
      handle = session.fs.file.new(path, 'wb')
      begin
        handle.write(marker)
      ensure
        handle.close
      end
      parent = nil
    elsif session.type == 'shell'
      command = "printf %s #{marker} > #{path}; printf 'MCPJAM_PID=%s\\nMCPJAM_PARENT=%s\\n' $$ $PPID; id"
      identity = session.shell_command_token(command)
      captured = identity.to_s.match(/^MCPJAM_PID=(\d+)\r?\nMCPJAM_PARENT=(\d+)\r?$/)
      raise IOError, "Remote shell did not identify its process: #{identity.inspect}" unless captured

      pid, parent = captured.captures.map { |value| Integer(value, 10) }
    else
      raise ArgumentError, "Unsupported real session type: #{session.type}"
    end
    {
      id: identifier, type: session.type, pid: pid, parent: parent, identity: identity, db_id: session.db_record&.id,
      via_exploit: session.via_exploit, via_payload: session.via_payload, session_host: session.session_host
    }
  end

  def self.shutdown(framework, identifier)
    session = framework.sessions.fetch(identifier)
    fresh = session.type == 'meterpreter' ? session.sys.process.getpid : session.shell_command_token('printf mcpjam-live')
    raise IOError, 'Remote shell stopped responding before shutdown' if session.type == 'shell' && !fresh.to_s.include?('mcpjam-live')

    DruidSessionControl.exit_remote(framework, identifier)
    { id: identifier, fresh_response: fresh, graceful_remote_exit_requested: true }
  end
end
