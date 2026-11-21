# frozen_string_literal: true

require 'base64'
require 'json'

# Record real check returns, requests and entry into the module's exploit body.
module TorchserveObservation
  OWNER = 'exploit/multi/http/torchserver_cve_2023_43654'

  def self.install(framework, directory)
    events = []
    source = File.expand_path('../../../modules/exploits/multi/http/torchserver_cve_2023_43654.rb', __dir__)
    trace = TracePoint.new(:call, :return) do |event|
      next unless %i[check exploit send_request_cgi generate_mar java_class_loader_start_service].include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.fullname == OWNER

      row = { event: event.event, method: event.method_id, source: event.path, object: receiver.object_id }
      row[:owner_exploit_body] = true if event.event == :call && event.method_id == :exploit && File.expand_path(event.path) == source
      if event.event == :call && event.method_id == :send_request_cgi
        options = event.binding.local_variable_get(:opts)
        row[:request] = { method: options['method'] || 'GET', uri: options['uri'], vars_get: options['vars_get'] }
      elsif event.event == :return
        result = event.return_value
        if result.is_a?(Msf::Exploit::CheckCode)
          row[:check] = { code: result.code, reason: result.reason }
        elsif event.method_id == :send_request_cgi && result
          row[:response] = { code: result.code, body_base64: Base64.strict_encode64(result.body.to_s.b) }
        end
      end
      events << row
      File.open(File.join(directory, 'torchserve-events.jsonl'), 'a') { |output| output.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@torchserve_events, events)
    framework.instance_variable_set(:@torchserve_trace, trace)
    trace.enable
    { installed: true }
  end
end
