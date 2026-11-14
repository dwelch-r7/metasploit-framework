# frozen_string_literal: true

require_relative '../druid_sessions/session_control'

# Observe real session readiness and use public APIs for remote effects and exit.
module MetabaseSessionControl
  def self.install(framework)
    DruidSessionControl.install(framework)
  end

  def self.proof(framework, identifier, path, marker)
    raise ArgumentError, 'Invalid controlled proof path' unless path.match?(%r{\A/tmp/module-target-metabase-session-[0-9_]+-[0-9]+\z})
    raise ArgumentError, 'Invalid controlled marker' unless marker.match?(/\A[a-z0-9_-]+\z/)

    session = framework.sessions.fetch(identifier)
    raise ArgumentError, "Unsupported real session type: #{session.type}" unless session.type == 'shell'

    identity = session.shell_command_token("printf %s #{marker} > #{path}; printf 'METABASE_PID=%s\\nMETABASE_PARENT=%s\\n' $$ $PPID; id")
    captured = identity.to_s.match(/^METABASE_PID=(\d+)\r?\nMETABASE_PARENT=(\d+)\r?$/)
    raise IOError, "Remote shell did not identify its process: #{identity.inspect}" unless captured

    pid, parent = captured.captures.map { |value| Integer(value, 10) }
    {
      id: identifier, type: session.type, pid: pid, parent: parent, identity: identity, db_id: session.db_record&.id,
      via_exploit: session.via_exploit, via_payload: session.via_payload, session_host: session.session_host
    }
  end

  def self.shutdown(framework, identifier)
    session = framework.sessions.fetch(identifier)
    raise ArgumentError, "Unsupported real session type: #{session.type}" unless session.type == 'shell'

    fresh = session.shell_command_token('printf metabase-live')
    raise IOError, 'Remote shell stopped responding before shutdown' unless fresh.to_s.include?('metabase-live')

    DruidSessionControl.exit_remote(framework, identifier)
    { id: identifier, fresh_response: fresh, graceful_remote_exit_requested: true }
  end
end
