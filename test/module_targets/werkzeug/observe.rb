# frozen_string_literal: true

require 'base64'
require 'json'

# Trace existing owner methods; no requests, authentication or results replaced.
module WerkzeugObservation
  OWNER = 'exploit/multi/http/werkzeug_debug_rce'

  def self.install(framework, directory)
    events = []
    methods = %i[check exploit config_invalid? secret_and_frame generated_cookie cookies execute_python check_code_exec]
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless methods.include?(event.method_id)
      next unless event.self.is_a?(Msf::Exploit::Remote) && event.self.fullname == OWNER

      row = { event: event.event, method: event.method_id, source: event.path, object: event.self.object_id }
      if event.event == :call && event.method_id == :execute_python
        command = event.binding.local_variable_get(:cmd)
        row[:command] = command.is_a?(String) ? { base64: Base64.strict_encode64(command.b) } : command
        row[:frame] = event.binding.local_variable_get(:frame)
        row[:cookie] = event.binding.local_variable_get(:cookies)
      elsif event.event == :return
        value = event.return_value
        if value.is_a?(Msf::Exploit::CheckCode)
          row[:check] = { code: value.code, reason: value.reason }
        elsif value.is_a?(String) && %i[cookies generated_cookie].include?(event.method_id)
          row[:cookie] = value
        elsif event.method_id == :execute_python
          row[:response] = value && { code: value.code, body_base64: Base64.strict_encode64(value.body.to_s.b) }
        end
      elsif event.event == :raise
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      end
      events << row
      File.open(File.join(directory, 'werkzeug-owner-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@werkzeug_events, events)
    framework.instance_variable_set(:@werkzeug_trace, trace)
    trace.enable
    { installed: trace.enabled? }
  end
end
