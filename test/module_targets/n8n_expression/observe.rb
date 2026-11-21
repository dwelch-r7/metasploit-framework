# frozen_string_literal: true

require 'base64'
require 'json'

# Passive original check/request/workflow observations; no delivery is replaced.
module N8nExpressionObservation
  OWNER = 'exploit/multi/http/n8n_workflow_expression_rce'

  def self.install(framework, directory)
    events = []
    source = File.expand_path('../../../modules/exploits/multi/http/n8n_workflow_expression_rce.rb', __dir__)
    trace = TracePoint.new(:call, :return) do |event|
      next unless %i[check exploit authenticate send_request_cgi create_malicious_workflow archive_workflow].include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.fullname == OWNER

      row = { event: event.event, method: event.method_id, source: event.path, object: receiver.object_id }
      row[:owner_exploit_body] = true if event.event == :call && event.method_id == :exploit && File.expand_path(event.path) == source
      if event.event == :call && event.method_id == :send_request_cgi
        options = event.binding.local_variable_get(:opts)
        row[:request] = { method: options['method'] || 'GET', uri: options['uri'], data: options['data'] }
      elsif event.event == :call && event.method_id == :create_malicious_workflow
        row[:command_base64] = Base64.strict_encode64(event.binding.local_variable_get(:cmd).b)
      elsif event.event == :return
        result = event.return_value
        if result.is_a?(Msf::Exploit::CheckCode)
          row[:check] = { code: result.code, reason: result.reason }
        elsif event.method_id == :send_request_cgi && result
          row[:response] = { code: result.code, body_base64: Base64.strict_encode64(result.body.to_s.b) }
        elsif event.method_id == :create_malicious_workflow
          row[:workflow_id] = receiver.instance_variable_get(:@workflow_id)
        end
      end
      events << row
      File.open(File.join(directory, 'n8n-expression-events.jsonl'), 'a') { |output| output.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@n8n_expression_events, events)
    framework.instance_variable_set(:@n8n_expression_trace, trace)
    trace.enable
    { installed: true }
  end
end
