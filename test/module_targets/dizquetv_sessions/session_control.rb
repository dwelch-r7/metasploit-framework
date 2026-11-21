# frozen_string_literal: true

require_relative '../laravel/session_control'
require_relative '../druid_sessions/session_control'

# Reuse public shell operations and passive real-session bootstrap events.
module DizquetvSessionControl
  def self.proof(framework, identifier, path, marker, php_shell)
    LaravelSessionControl.proof(framework, identifier, path, marker, php_shell, component: 'dizquetv')
  end

  def self.shutdown(framework, identifier)
    LaravelSessionControl.shutdown(framework, identifier, component: 'dizquetv')
  end

  def self.install(framework)
    DruidSessionControl.install(framework)
  end
end
