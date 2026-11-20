# frozen_string_literal: true

require_relative 'acceptance'
require_relative '../laravel/sessions'

# Apply the common session lifecycle checks to InvoiceShelf cookie delivery.
module InvoiceShelfSessions
  include InvoiceShelfTarget
  include LaravelSessions

  FAMILIES = LaravelSessions::FAMILIES.except('fetch').freeze

  def session_control_name
    'InvoiceShelfSessionControl'
  end

  def session_health_path
    '/api/v1/app/version'
  end
end
