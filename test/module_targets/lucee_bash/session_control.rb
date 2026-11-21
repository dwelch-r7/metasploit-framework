# frozen_string_literal: true

require_relative '../laravel/session_control'

# Preserve the public shell proof and shutdown APIs used by other native labs.
module LuceeSessionControl
  def self.proof(framework, identifier, path, marker, php_shell)
    LaravelSessionControl.proof(framework, identifier, path, marker, php_shell, component: 'lucee')
  end

  def self.shutdown(framework, identifier)
    LaravelSessionControl.shutdown(framework, identifier, component: 'lucee')
  end
end
