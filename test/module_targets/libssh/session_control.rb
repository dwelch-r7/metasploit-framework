# frozen_string_literal: true

require_relative '../druid_sessions/session_control'

# Reuse the passive bootstrap observer; exercise the real command-shell API.
module LibsshSessionControl
  def self.proof(framework, identifier, path, marker)
    raise ArgumentError, 'Unexpected lab proof path' unless path.match?(%r{\A/tmp/libssh-lab/owner-[0-9_-]+\z})
    raise ArgumentError, 'Unexpected lab marker' unless marker.match?(/\Alibssh-[0-9_-]+\z/)

    session = framework.sessions.fetch(identifier)
    command = "printf %s #{marker} > #{path};printf '\\nPID=%s UID=%s TTY=' $$ $(id -u);if test -t 0;then printf yes;else printf no;fi;printf '\\n'"
    output = session.shell_command_token(command)
    { id: identifier, type: session.type, owner: session.via_exploit, db_id: session.db_record&.id, peer: session.tunnel_peer, command: command, output: output }
  end

  def self.close(framework, identifier)
    framework.sessions[identifier]&.shell_close
    { id: identifier, public_close_requested: true }
  end
end
