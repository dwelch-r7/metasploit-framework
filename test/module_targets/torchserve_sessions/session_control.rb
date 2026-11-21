# frozen_string_literal: true

require_relative '../laravel/session_control'

# Preserve the existing public Meterpreter proof and remote shutdown operations.
module TorchserveSessionControl
  def self.proof(framework, identifier, path, marker, php_shell)
    LaravelSessionControl.proof(framework, identifier, path, marker, php_shell, component: 'torchserve')
  end

  def self.shutdown(framework, identifier)
    LaravelSessionControl.shutdown(framework, identifier, component: 'torchserve')
  end
end
