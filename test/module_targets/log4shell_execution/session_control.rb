# frozen_string_literal: true

require 'json'

# Public session RPC only; the owner, generated payload and protocol stay real.
module Log4shellSessionControl
  # @param framework [Msf::Framework] the running Framework
  # @param identifier [Integer] the real session identifier
  # @param path [String] the controlled target proof path
  # @param value [String] the per-run marker
  # @return [Hash] real session identity and observed remote PID
  def self.proof(framework, identifier, path, value)
    raise ArgumentError, 'Invalid proof path' unless path.match?(%r{\A/tmp/module-target-log4shell-own-[a-z0-9_-]+\z})
    raise ArgumentError, 'Invalid marker' unless value.match?(/\A[a-z0-9_-]+\z/)

    session = framework.sessions.fetch(identifier)
    if session.type == 'meterpreter'
      pid = session.sys.process.getpid
      identity = session.sys.config.getuid
      file = session.fs.file.new(path, 'wb')
      begin
        file.write(value)
      ensure
        file.close
      end
    elsif session.type == 'shell'
      identity = session.shell_command_token("printf '%s' '#{value}' > #{path}; printf 'LOG4J_PID=%s\\n' $$; id")
      captured = identity.to_s[/^LOG4J_PID=(\d+)\r?$/, 1]
      raise IOError, "Remote shell did not return a PID: #{identity.inspect}" unless captured

      pid = Integer(captured, 10)
    else
      raise ArgumentError, "Unsupported session type #{session.type}"
    end
    { id: identifier, type: session.type, pid: pid, identity: identity, peer: session.tunnel_peer, db_id: session.db_record&.id }
  end

  # @param framework [Msf::Framework] the running Framework
  # @param identifier [Integer] the live session identifier
  # @return [Hash] the issued public shutdown operation
  def self.shutdown(framework, identifier)
    session = framework.sessions.fetch(identifier)
    # Take a fresh remote response immediately before shutdown.
    if session.type == 'meterpreter'
      response = session.sys.process.getpid
      session.core.shutdown
    else
      response = session.shell_command_token('printf log4shell-live')
      raise IOError, 'Remote shell is not responsive' unless response.to_s.include?('log4shell-live')

      session.shell_write("exit\n")
    end
    { id: identifier, fresh_response: response, remote_shutdown_requested: true }
  end
end
