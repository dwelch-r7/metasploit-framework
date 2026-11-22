# frozen_string_literal: true

require 'base64'
require 'json'

# Observe the installed owner, retaining its real HTTP transport and payloads.
module LinuxkiObservation
  OWNER = 'exploit/linux/http/linuxki_rce'

  def self.install(framework, directory)
    events = []
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless %i[check exploit execute_command send_request_cgi].include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.fullname == OWNER

      row = { event: event.event, method: event.method_id, source: event.path, object: receiver.object_id }
      if event.event == :call
        row[:owner_exploit_body] = true if event.method_id == :exploit && event.path.end_with?('/linuxki_rce.rb')
        row[:command_base64] = Base64.strict_encode64(event.binding.local_variable_get(:cmd).b) if event.method_id == :execute_command
        if event.method_id == :send_request_cgi
          options = event.binding.local_variable_get(:opts)
          row[:request] = { method: options['method'], uri: options['uri'], vars_get_base64: options.fetch('vars_get', {}).transform_values { |value| Base64.strict_encode64(value.to_s.b) } }
        end
      elsif event.event == :return
        value = event.return_value
        row[:check] = { code: value.code, reason: value.reason } if value.is_a?(Msf::Exploit::CheckCode)
        if event.method_id == :send_request_cgi && value
          row[:response] = { code: value.code, body_base64: Base64.strict_encode64(value.body.to_s.b) }
        end
      else
        error = event.raised_exception
        row[:error] = { type: error.class.name, message: error.message }
      end
      events << row
      File.open(File.join(directory, 'linuxki-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@linuxki_events, events)
    framework.instance_variable_set(:@linuxki_trace, trace)
    trace.enable
    { installed: true }
  end
end
