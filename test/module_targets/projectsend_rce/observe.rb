# frozen_string_literal: true

require 'base64'
require 'json'

# Observe original methods, encoded payloads and raw HTTP without replacing them.
module ProjectsendRceObservation
  OWNER = 'exploit/linux/http/projectsend_unauth_rce'
  METHODS = %i[check exploit cleanup register_new_user upload_file calculate_potential_filenames trigger_shell get_write_exec_payload send_request_cgi].freeze

  def self.install(framework, directory)
    events = []
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless event.self.is_a?(Msf::Exploit::Remote) && event.self.fullname == OWNER
      next unless event.event == :raise || METHODS.include?(event.method_id)

      row = { event: event.event, method: event.method_id, source: event.path, object: event.self.object_id }
      if event.event == :raise
        error = event.raised_exception
        row[:error] = { type: error.class.name, message: error.message }
      elsif event.event == :call && event.method_id == :send_request_cgi
        options = event.binding.local_variable_get(:opts)
        row[:request] = { method: options['method'] || 'GET', uri: options['uri'], vars_get: options['vars_get'], vars_post: options['vars_post'], data_base64: options['data'] && Base64.strict_encode64(options['data'].b), content_type: options['ctype'] }
      elsif event.event == :call && event.method_id == :get_write_exec_payload
        row[:payload] = { name: event.self.datastore['PAYLOAD'], command: event.self.datastore['CMD'] }
      elsif event.event == :return
        result = event.return_value
        row[:check] = { code: result.code, reason: result.reason } if result.is_a?(Msf::Exploit::CheckCode)
        row[:response] = { code: result.code, headers: result.headers, body_base64: Base64.strict_encode64(result.body.to_s.b) } if event.method_id == :send_request_cgi && result
        row[:program_base64] = Base64.strict_encode64(result.b) if event.method_id == :get_write_exec_payload && result
        row[:filenames] = result if event.method_id == :calculate_potential_filenames
        row[:owner] = { username: event.self.instance_variable_get(:@username), file_id: event.self.instance_variable_get(:@file_id) } if %i[exploit cleanup].include?(event.method_id)
      end
      events << row
      File.open(File.join(directory, 'projectsend-rce-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@projectsend_rce_events, events)
    framework.instance_variable_set(:@projectsend_rce_trace, trace)
    trace.enable
    { installed: true }
  end
end
