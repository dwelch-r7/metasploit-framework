# frozen_string_literal: true

require_relative 'acceptance'
require_relative '../laravel/sessions'

# Apply common session lifecycle checks to the real Invoice Ninja route owner.
module InvoiceNinjaSessions
  include InvoiceNinjaTarget
  include LaravelSessions

  FAMILIES = LaravelSessions::FAMILIES

  def rc_resource_roles
    %w[target database reporting_db]
  end

  def session_control_name
    'InvoiceNinjaSessionControl'
  end

  def session_health_path
    '/login'
  end
end
