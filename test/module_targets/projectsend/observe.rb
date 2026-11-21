# frozen_string_literal: true

require 'base64'
require 'json'

# Passive original-method and HTTP observations; no owner behavior is replaced.
module ProjectsendObservation
  OWNER = 'exploit/linux/http/projectsend_unauth_rce'

  def self.install(framework, directory)
    events = []
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless event.self.is_a?(Msf::Exploit::Remote) && event.self.fullname == OWNER
      next unless event.event == :raise || %i[check cleanup exploit get_csrf_token send_request_cgi].include?(event.method_id)

      row = { event: event.event, method: event.method_id, source: event.path, object: event.self.object_id }
      if event.event == :raise
        error = event.raised_exception
        row[:error] = { type: error.class.name, message: error.message }
        row[:error][:reason] = event.self.fail_reason if error.is_a?(Msf::Exploit::Failed)
      elsif event.event == :call && event.method_id == :send_request_cgi
        options = event.binding.local_variable_get(:opts)
        row[:request] = { method: options['method'] || 'GET', uri: options['uri'], vars_get: options['vars_get'], vars_post: options['vars_post'] }
      elsif event.event == :return
        result = event.return_value
        row[:check] = { code: result.code, reason: result.reason } if result.is_a?(Msf::Exploit::CheckCode)
        row[:response] = { code: result.code, body_base64: Base64.strict_encode64(result.body.to_s.b) } if event.method_id == :send_request_cgi && result
      end
      events << row
      File.open(File.join(directory, 'projectsend-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@projectsend_events, events)
    framework.instance_variable_set(:@projectsend_trace, trace)
    trace.enable
    { installed: true }
  end
end
