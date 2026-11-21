# frozen_string_literal: true

require_relative '../calibre_python/acceptance'

# Test the payload actually chosen by the console after selecting Linux TARGET 1.
module CalibreFetchSessions
  include CalibreSessions

  FAMILIES = { 'fetch' => [1, 'cmd/linux/http/x64/meterpreter/reverse_tcp', 'meterpreter'] }.freeze

  def session_families
    FAMILIES
  end

  def session_default_options
    { 'fetch' => ['PAYLOAD'] }
  end
end
