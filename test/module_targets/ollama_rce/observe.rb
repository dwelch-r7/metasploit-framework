# frozen_string_literal: true

require 'base64'
require 'json'
require 'net/http'

# Observe original owner returns and physical state without changing delivery.
module OllamaObservation
  OWNER = 'exploit/linux/http/ollama_rce_cve_2024_37032'

  def self.install(framework, directory, observer)
    events = []
    source = File.expand_path('../../../modules/exploits/linux/http/ollama_rce_cve_2024_37032.rb', __dir__)
    trace = TracePoint.new(:call, :return) do |event|
      next unless %i[check exploit send_request_cgi generate_payload_so prepare_payloads trigger_rce].include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.fullname == OWNER

      row = { event: event.event, method: event.method_id, source: event.path, object: receiver.object_id }
      row[:owner_exploit_body] = true if event.event == :call && event.method_id == :exploit && File.expand_path(event.path) == source
      if event.event == :call && event.method_id == :send_request_cgi
        options = event.binding.local_variable_get(:opts)
        row[:request] = { method: options['method'] || 'GET', uri: options['uri'], data: options['data'] }
      elsif event.event == :call && event.method_id == :trigger_rce
        # Host HTTP only: never exec a dynamic observer inside an armed target.
        uri = URI(observer + '/snapshot')
        row[:before_trigger] = JSON.parse(Net::HTTP.start(uri.host, uri.port, nil, open_timeout: 3, read_timeout: 5) { |http| http.get(uri.request_uri).body })
      elsif event.event == :return
        result = event.return_value
        if result.is_a?(Msf::Exploit::CheckCode)
          row[:check] = { code: result.code, reason: result.reason }
        elsif event.method_id == :send_request_cgi && result
          row[:response] = { code: result.code, body_base64: Base64.strict_encode64(result.body.to_s.b) }
        elsif event.method_id == :generate_payload_so
          row[:library_base64] = Base64.strict_encode64(result.b)
        elsif event.method_id == :prepare_payloads
          row[:prepared] = %i[so_path preload_blob dummy_name trigger_namespace evil_namespace].to_h do |name|
            [name, receiver.instance_variable_get(('@' + name.to_s).to_sym)]
          end
        end
      end
      events << row
      File.open(File.join(directory, 'ollama-events.jsonl'), 'a') { |output| output.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@ollama_events, events)
    framework.instance_variable_set(:@ollama_trace, trace)
    trace.enable
    { installed: true }
  end
end
