# frozen_string_literal: true

require_relative '../laravel/session_control'

# Preserve the established public Meterpreter proof and shutdown operations.
module OllamaSessionControl
  def self.proof(framework, identifier, path, marker, php_shell)
    LaravelSessionControl.proof(framework, identifier, path, marker, php_shell, component: 'ollama')
  end

  def self.shutdown(framework, identifier)
    LaravelSessionControl.shutdown(framework, identifier, component: 'ollama')
  end
end
