# frozen_string_literal: true

require_relative '../laravel/session_control'
require_relative '../druid_sessions/session_control'

# Reuse public session operations and passive bootstrap events.
module OpenDcimSessionControl
  def self.proof(framework, identifier, path, marker, php_shell)
    LaravelSessionControl.proof(framework, identifier, path, marker, php_shell, component: 'opendcim')
  end

  def self.shutdown(framework, identifier)
    LaravelSessionControl.shutdown(framework, identifier, component: 'opendcim')
  end

  def self.install(framework)
    DruidSessionControl.install(framework)
  end
end
