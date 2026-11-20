# frozen_string_literal: true

require_relative '../laravel/session_control'

# Preserve the component entry points while sharing public session API checks.
module InvoiceNinjaSessionControl
  def self.proof(framework, identifier, path, marker, php_shell)
    LaravelSessionControl.proof(framework, identifier, path, marker, php_shell, component: 'invoiceninja')
  end

  def self.shutdown(framework, identifier)
    LaravelSessionControl.shutdown(framework, identifier, component: 'invoiceninja')
  end
end
