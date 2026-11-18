# frozen_string_literal: true

require 'base64'
require 'digest'

# Passive owner calls; filter methods before resolving paths on SQLi HTTP calls.
module SuiteCrmObservation
  METHODS = %i[check authenticate run get_user_names get_user_hashes init_sqli].freeze

  def self.install(framework)
    source = File.expand_path('modules/auxiliary/gather/suite_crm_export_sqli.rb')
    events = []
    trace = TracePoint.new(:call, :return) do |event|
      next unless METHODS.include?(event.method_id)
      next unless event.path == source || File.expand_path(event.path) == source

      row = { event: event.event, method: event.method_id, object: event.self.object_id, auto_check: event.self.datastore['AutoCheck'], count: event.self.datastore['COUNT'] }
      if event.event == :return
        value = event.return_value
        if event.method_id == :check && value.respond_to?(:code) && value.respond_to?(:message)
          row[:result] = { code: value.code, reason: value.message }
        elsif event.method_id == :authenticate
          row[:result] = value
        elsif event.method_id == :get_user_names && value.is_a?(Array)
          row[:names_base64] = value.map { |name| Base64.strict_encode64(name.b) }
        else
          row[:result_class] = value.class.name
        end
      end
      events << row
    end
    framework.instance_variable_set(:@suitecrm_events, events)
    framework.instance_variable_set(:@suitecrm_trace, trace)
    trace.enable
    { installed: true, owner_sha256: Digest::SHA256.file(source).hexdigest, config: Msf::Config.config_directory }
  end
end
