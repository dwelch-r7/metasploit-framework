# frozen_string_literal: true

require 'base64'
require 'json'
require 'time'

# Observe genuine owner calls and replies without replacing their behavior.
module LangflowAutoObservation
  OWNER = 'exploit/multi/http/langflow_unauth_rce_cve_2026_9198'

  def self.install(framework, directory)
    events = []
    filename = File.join(directory, 'langflow-auto-owner-events.jsonl')
    File.write(filename, '')
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless %i[check exploit get_token send_request_cgi store_loot].include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.fullname == OWNER

      row = { event: event.event, method: event.method_id, source: event.path, object: receiver.object_id, at: Time.now.utc.iso8601(6) }
      if event.event == :call && event.method_id == :exploit
        # Console run arguments belong to execution replicants, while the
        # selected UI object's datastore can retain an earlier value.
        row[:options] = {
          'PAYLOAD' => receiver.datastore['PAYLOAD'],
          'MeterpreterTryToFork' => receiver.datastore['MeterpreterTryToFork']
        }
      end
      if event.event == :return
        result = event.return_value
        row[:check] = { code: result.code, reason: result.reason } if result.is_a?(Msf::Exploit::CheckCode)
        row[:response] = { code: result.code, body_base64: Base64.strict_encode64(result.body.to_s.b) } if event.method_id == :send_request_cgi && result
        row[:loot_path] = result if event.method_id == :store_loot
      elsif event.event == :raise
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      end
      events << row
      File.open(filename, 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@langflow_auto_events, events)
    framework.instance_variable_set(:@langflow_auto_trace, trace)
    trace.enable
    { installed: true }
  end
end
