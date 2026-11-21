# frozen_string_literal: true

require 'base64'
require 'json'

# Observe the actual owner and HTTP mixin without changing their behavior.
module Text4shellObservation
  OWNER = 'exploit/multi/http/apache_commons_text4shell'
  METHODS = %i[check exploit execute_command send_exp send_request_cgi].freeze

  def self.install(framework, directory)
    events = []
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless event.self.is_a?(Msf::Exploit::Remote) && event.self.fullname == OWNER
      next unless event.event == :raise || METHODS.include?(event.method_id)

      row = { event: event.event, method: event.method_id, source: event.path, object: event.self.object_id }
      if event.event == :raise
        error = event.raised_exception
        row[:error] = { type: error.class.name, message: error.message }
        row[:error][:reason] = event.self.fail_reason if error.is_a?(Msf::Exploit::Failed)
      elsif event.event == :call
        if event.method_id == :send_request_cgi
          options = event.binding.local_variable_get(:opts)
          row[:request] = { method: options['method'] || 'GET', uri: options['uri'], query: options['vars_get'], form: options['vars_post'] }
        elsif event.method_id == :execute_command
          row[:command] = event.binding.local_variable_get(:cmd)
          row[:payload] = { name: event.self.datastore['PAYLOAD'], command: event.self.datastore['CMD'] }
        end
      elsif event.event == :return
        result = event.return_value
        row[:check] = { code: result.code, reason: result.reason } if result.is_a?(Msf::Exploit::CheckCode)
        row[:response] = { code: result.code, headers: result.headers, body_base64: Base64.strict_encode64(result.body.to_s.b) } if event.method_id == :send_request_cgi && result
      end
      events << row
      File.open(File.join(directory, 'text4shell-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@text4shell_events, events)
    framework.instance_variable_set(:@text4shell_trace, trace)
    trace.enable
    { installed: true }
  end
end
