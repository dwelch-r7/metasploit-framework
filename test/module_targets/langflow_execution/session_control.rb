# frozen_string_literal: true

# Python command-shell payloads execute each command in a new child shell.
module LangflowSessionControl
  # @param framework [Msf::Framework] the real Framework
  # @param identifier [Integer] the real session identifier
  # @param path [String] controlled proof path
  # @param marker [String] exact controlled file bytes
  # @return [Hash] remote identity, interpreter PID and reporting row
  def self.proof(framework, identifier, path, marker)
    raise ArgumentError, 'Invalid proof path' unless path.match?(%r{\A/tmp/module-target-langflow-own-[a-z0-9_-]+\z})
    raise ArgumentError, 'Invalid marker' unless marker.match?(/\A[a-z0-9_-]+\z/)

    session = framework.sessions.fetch(identifier)
    if session.type == 'meterpreter'
      pid = session.sys.process.getpid
      identity = session.sys.config.getuid
      file = session.fs.file.new(path, 'wb')
      begin
        file.write(marker)
      ensure
        file.close
      end
    else
      raise ArgumentError, 'Expected a Python command shell' unless session.type == 'shell'

      identity = session.shell_command_token("printf %s #{marker} > #{path}; printf 'LANGFLOW_PARENT=%s\\n' $PPID; id")
      captured = identity.to_s[/^LANGFLOW_PARENT=(\d+)\r?$/, 1]
      raise IOError, "Remote shell did not identify its parent: #{identity.inspect}" unless captured

      pid = Integer(captured, 10)
    end
    { id: identifier, type: session.type, pid: pid, identity: identity, db_id: session.db_record&.id }
  end

  # @param framework [Msf::Framework] the real Framework
  # @param identifier [Integer] the live session identifier
  # @return [Hash] actual public shutdown operation
  def self.shutdown(framework, identifier)
    session = framework.sessions.fetch(identifier)
    if session.type == 'meterpreter'
      response = session.sys.process.getpid
      session.core.shutdown
    else
      response = session.shell_command_token('printf langflow-live')
      raise IOError, 'Remote shell is not responsive' unless response.to_s.include?('langflow-live')

      # Closing the transport lets the genuine Python receive loop observe EOF.
      session.kill
    end
    { id: identifier, fresh_response: response, shutdown_requested: true }
  end
end
