# frozen_string_literal: true

require_relative '../laravel/observe'

# Select the Invoice Ninja owner without changing its request or crypto behavior.
module InvoiceNinjaObservation
  OWNER = 'exploit/linux/http/invoiceninja_unauth_rce_cve_2024_55555'

  def self.install(framework, directory)
    LaravelObservation.install(framework, directory, owner: OWNER, component: 'invoiceninja')
  end
end
