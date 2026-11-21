# frozen_string_literal: true

require_relative '../laravel/session_control'
require_relative '../druid_sessions/session_control'

# Reuse public Meterpreter APIs and post-bootstrap session events.
module ProjectsendSessionControl
  def self.proof(framework, identifier, path, marker, php_shell)
    LaravelSessionControl.proof(framework, identifier, path, marker, php_shell, component: 'projectsend')
  end

  def self.shutdown(framework, identifier)
    LaravelSessionControl.shutdown(framework, identifier, component: 'projectsend')
  end

  def self.install(framework)
    DruidSessionControl.install(framework)
  end
end
