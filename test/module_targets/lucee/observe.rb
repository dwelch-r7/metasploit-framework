# frozen_string_literal: true

require 'base64'
require 'json'

# Observe real owners and their helpers without replacing a target or producer.
module LuceeObservation
  OWNERS = %w[exploit/linux/http/lucee_admin_imgprocess_file_write exploit/multi/http/lucee_scheduled_job].freeze

  def self.parameters(values)
    values&.transform_values { |value| value.nil? ? nil : Base64.strict_encode64(value.to_s.b) }
  end

  def self.install(framework, directory)
    events = []
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless %i[check exploit write_file write_cfml_stub execute_command authenticate create_job execute_job webroot cfm_stub send_request_cgi].include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && OWNERS.include?(receiver.fullname)

      row = { event: event.event, method: event.method_id, owner: receiver.fullname, source: event.path, object: receiver.object_id }
      if event.event == :call
        if event.method_id == :write_file
          row[:name] = event.binding.local_variable_get(:name)
          contents = event.binding.local_variable_get(:contents)
          row[:contents_base64] = Base64.strict_encode64(contents.b) if contents
        elsif event.method_id == :execute_command
          row[:command_base64] = Base64.strict_encode64(event.binding.local_variable_get(:cmd).b)
        elsif %i[create_job execute_job].include?(event.method_id)
          row[:task] = event.binding.local_variable_get(:payload_base)
        elsif event.method_id == :send_request_cgi
          options = event.binding.local_variable_get(:opts)
          row[:request] = { method: options['method'] || 'GET', uri: options['uri'], vars_get_base64: parameters(options['vars_get']), vars_post_base64: parameters(options['vars_post']) }
        end
      elsif event.event == :return
        value = event.return_value
        if value.is_a?(Msf::Exploit::CheckCode)
          row[:check] = { code: value.code, reason: value.reason }
        elsif event.method_id == :cfm_stub
          row[:stub_base64] = Base64.strict_encode64(value.b)
        elsif event.method_id == :webroot
          row[:webroot] = value&.dup
        elsif event.method_id == :send_request_cgi && value
          row[:response] = { code: value.code, body_base64: Base64.strict_encode64(value.body.to_s.b), location: value.headers['Location'] }
        end
      elsif event.event == :raise
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      end
      events << row
      File.open(File.join(directory, 'lucee-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@lucee_events, events)
    framework.instance_variable_set(:@lucee_trace, trace)
    trace.enable
    { installed: true }
  end
end
