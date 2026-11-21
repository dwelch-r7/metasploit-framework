# frozen_string_literal: true

require_relative '../laravel/session_control'

# The shared Meterpreter branch uses public file, identity and shutdown APIs.
module CalibreSessionControl
  def self.proof(framework, identifier, path, marker, php_shell)
    LaravelSessionControl.proof(framework, identifier, path, marker, php_shell, component: 'calibre')
  end

  def self.shutdown(framework, identifier)
    LaravelSessionControl.shutdown(framework, identifier, component: 'calibre')
  end
end
