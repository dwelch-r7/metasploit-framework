# frozen_string_literal: true

require_relative '../laravel/session_control'

# Apply the shared public shell APIs with Ignition's proof namespace.
module IgnitionSessionControl
  def self.proof(framework, identifier, path, marker, php_shell)
    LaravelSessionControl.proof(framework, identifier, path, marker, php_shell, component: 'ignition')
  end

  def self.shutdown(framework, identifier)
    LaravelSessionControl.shutdown(framework, identifier, component: 'ignition')
  end
end
