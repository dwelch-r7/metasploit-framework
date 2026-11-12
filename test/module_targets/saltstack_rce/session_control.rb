# frozen_string_literal: true

require 'base64'
require 'digest'
require 'shellwords'
require_relative '../druid_sessions/session_control'

# Uses actual session RPC/command APIs; the observer changes no handler behavior.
module SaltSessionControl
  def self.proof(framework, identifier, path, value)
    raise ArgumentError, 'Invalid proof path' unless path.match?(%r{\A/tmp/module-target-salt-proof-[a-f0-9]+\z})

    session = framework.sessions.fetch(identifier)
    result = {
      id: identifier, type: session.type, peer: session.tunnel_peer,
      db_id: session.db_record.id, via_exploit: session.via_exploit,
      via_payload: session.via_payload
    }
    if session.type == 'meterpreter'
      result.merge!(pid: session.sys.process.getpid, identity: session.sys.config.getuid,
                    role: session.sys.config.getenv('MSF_MODULE_TARGET_ROLE'),
                    token: session.sys.config.getenv('MSF_MODULE_TARGET_TOKEN'))
      file = session.fs.file.new(path, 'wb')
      begin
        result[:bytes_written] = file.write(value)
      ensure
        file.close
      end
    elsif session.type == 'shell'
      command = "printf %s #{Shellwords.escape(value)} > #{path}; printf 'SALT_ROLE=%s\\nSALT_TOKEN=%s\\nSALT_COMMAND_PID=%s\\n' \"$MSF_MODULE_TARGET_ROLE\" \"$MSF_MODULE_TARGET_TOKEN\" \"$$\"; id -u"
      output = session.shell_command_token(command)
      result.merge!(role: output.to_s[/^SALT_ROLE=([^\r\n]+)/, 1],
                    token: output.to_s[/^SALT_TOKEN=([^\r\n]+)/, 1],
                    command_pid: output.to_s[/^SALT_COMMAND_PID=(\d+)/, 1],
                    raw_command_output: output)
    else
      raise ArgumentError, "Unsupported session type: #{session.type}"
    end
    result
  end

  def self.close(framework, identifier)
    session = framework.sessions.fetch(identifier)
    if session.type == 'meterpreter'
      session.core.shutdown
    else
      # The SSL command payload spawns a new shell for each received command;
      # sending `exit` would close only that child. Close its actual transport.
      session.shell_close
      session.kill
    end
    { id: identifier, closed: true }
  end
end
