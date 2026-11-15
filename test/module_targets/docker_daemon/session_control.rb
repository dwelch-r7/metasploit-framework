# frozen_string_literal: true

require_relative '../druid_sessions/session_control'

# Use real public session APIs; remote effects are independently read on target.
module DockerDaemonSessionControl
  def self.install(framework)
    DruidSessionControl.install(framework)
  end

  def self.proof(framework, identifier, path, marker)
    raise ArgumentError, 'Invalid controlled marker path' unless path.match?(%r{\A/tmp/module-target-docker-session-[0-9_]+-[0-9]+\z})
    raise ArgumentError, 'Invalid controlled marker' unless marker.match?(/\A[a-z0-9_-]+\z/)

    session = framework.sessions.fetch(identifier)
    if session.type == 'meterpreter'
      file = session.fs.file.new(path, 'wb')
      begin
        file.write(marker.b)
      ensure
        file.close
      end
      pid = session.sys.process.getpid
      identity = session.sys.config.getuid
    elsif session.type == 'shell'
      # The Python payload starts a fresh /bin/sh for each command. Its parent
      # is the persistent Python loop; $$ would identify an already exited child.
      pid_expression = session.via_payload == 'payload/python/shell_reverse_tcp' ? '$PPID' : '$$'
      output = session.shell_command_token("printf %s #{marker} > #{path}; printf 'DOCKER_PID=%s\\n' #{pid_expression}; id")
      captured = output.to_s[/^DOCKER_PID=(\d+)\r?$/, 1]
      raise IOError, "Remote shell did not return its PID: #{output.inspect}" unless captured

      pid = Integer(captured, 10)
      identity = output
    else
      raise ArgumentError, "Unsupported real session type: #{session.type}"
    end
    {
      id: identifier, type: session.type, pid: pid, identity: identity,
      via_exploit: session.via_exploit, via_payload: session.via_payload,
      session_host: session.session_host, db_id: session.db_record&.id
    }
  end

  def self.shutdown(framework, identifier)
    session = framework.sessions.fetch(identifier)
    case session.type
    when 'meterpreter'
      session.sys.process.getpid
    when 'shell'
      response = session.shell_command_token('printf docker-daemon-live')
      raise IOError, 'Remote shell stopped responding before exit' unless response.to_s.include?('docker-daemon-live')

      if session.via_payload == 'payload/python/shell_reverse_tcp'
        # `exit` only terminates one Popen child of this payload. Request remote
        # termination of the actual Python loop and verify its death natively.
        output = session.shell_command_token("printf 'DOCKER_PID=%s\\n' $PPID")
        captured = output.to_s[/^DOCKER_PID=(\d+)\r?$/, 1]
        raise IOError, 'Python command loop did not identify its PID' unless captured && Integer(captured, 10) > 1

        session.shell_write("kill -TERM #{captured}\n")
        return { id: identifier, graceful_remote_exit_requested: true, mechanism: 'SIGTERM to remote Python command loop', pid: Integer(captured, 10) }
      end
    else
      raise ArgumentError, "Unsupported real session type: #{session.type}"
    end
    DruidSessionControl.exit_remote(framework, identifier)
  end
end
