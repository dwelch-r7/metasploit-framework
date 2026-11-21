# frozen_string_literal: true

require_relative '../laravel/session_control'

# The stock Perl payload runs a child shell for each line until transport EOF.
module LaravelTokenSessionControl
  def self.proof(framework, identifier, path, marker, _php_shell)
    LaravelSessionControl.proof(framework, identifier, path, marker, true, component: 'laraveltoken')
  end

  def self.shutdown(framework, identifier)
    session = framework.sessions.fetch(identifier)
    response = session.shell_command_token('printf laraveltoken-live')
    raise IOError, 'Perl shell is not responsive' unless response.to_s.include?('laraveltoken-live')

    session.shell_close
    framework.sessions[identifier]&.kill
    { id: identifier, fresh_response: response, shutdown_requested: true }
  end
end
