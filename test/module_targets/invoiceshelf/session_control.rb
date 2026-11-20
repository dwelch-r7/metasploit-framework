# frozen_string_literal: true

# Public session APIs; the PHP shell creates a child shell for each command.
module InvoiceShelfSessionControl
  def self.proof(framework, identifier, path, marker, php_shell)
    raise ArgumentError, 'Invalid proof path' unless path.match?(%r{\A/tmp/module-target-invoiceshelf-session-[a-z0-9_-]+\z})
    raise ArgumentError, 'Invalid marker' unless marker.match?(/\A[a-z0-9_-]+\z/)

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
    else
      raise ArgumentError, 'Expected a shell' unless session.type == 'shell'

      variable = php_shell ? '$PPID' : '$$'
      identity = session.shell_command_token("printf %s #{marker} > #{path}; printf 'INVOICESHELF_PID=%s\\n' #{variable}; id")
      captured = identity.to_s[/^INVOICESHELF_PID=(\d+)\r?$/, 1]
      raise IOError, "Shell returned no PID: #{identity.inspect}" unless captured

      pid = Integer(captured, 10)
    end
    { id: identifier, type: session.type, pid: pid, identity: identity, db_id: session.db_record&.id }
  end

  def self.shutdown(framework, identifier)
    session = framework.sessions.fetch(identifier)
    if session.type == 'meterpreter'
      response = session.sys.process.getpid
      session.core.shutdown
    else
      response = session.shell_command_token('printf invoiceshelf-live')
      raise IOError, 'Shell is not responsive' unless response.to_s.include?('invoiceshelf-live')

      session.shell_write("exit\n")
    end
    { id: identifier, fresh_response: response, shutdown_requested: true }
  end
end
