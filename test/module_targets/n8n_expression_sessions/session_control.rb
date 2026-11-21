# frozen_string_literal: true

require_relative '../laravel/session_control'
require_relative '../rocketmq_sessions/session_control'
require_relative '../druid_sessions/session_control'

# Original payload bytes and public Meterpreter operations; no method stubs.
module N8nSessionControl
  def self.proof(framework, identifier, path, marker, php_shell)
    LaravelSessionControl.proof(framework, identifier, path, marker, php_shell, component: 'nworkflow')
  end

  def self.shutdown(framework, identifier)
    LaravelSessionControl.shutdown(framework, identifier, component: 'nworkflow')
  end

  def self.install(framework, directory)
    trace = TracePoint.new(:return) do |event|
      next unless event.method_id == :payload_response && event.self.is_a?(Msf::Payload)
      next unless event.self.refname == 'cmd/linux/http/x64/meterpreter_reverse_tcp'

      response = event.return_value
      row = { payload: event.self.refname, sha256: Digest::SHA256.hexdigest(response.body), base64: Base64.strict_encode64(response.body) }
      File.open(File.join(directory, 'n8n-session-fetch.jsonl'), 'a') { |output| output.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@n8n_session_fetch_trace, trace)
    trace.enable
    DruidSessionControl.install(framework)
  end
end
