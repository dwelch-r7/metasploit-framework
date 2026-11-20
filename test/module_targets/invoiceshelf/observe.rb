# frozen_string_literal: true

require_relative '../laravel/observe'

# Select the InvoiceShelf owner without changing its request or crypto behavior.
module InvoiceShelfObservation
  OWNER = 'exploit/linux/http/invoiceshelf_unauth_rce_cve_2024_55556'

  def self.install(framework, directory)
    LaravelObservation.install(framework, directory, owner: OWNER, component: 'invoiceshelf')
  end
end
