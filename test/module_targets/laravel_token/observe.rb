# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'

# Observe real crypto/discovery/HTTP methods without replacing implementation.
module LaravelTokenObservation
  OWNER = 'exploit/unix/http/laravel_token_unserialize_exec'

  def self.install(framework, directory)
    events = []
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless %i[check exploit check_appkey env_leak framework_leak test_appkey generate_token send_request_cgi].include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.fullname == OWNER

      row = { event: event.event, method: event.method_id, source: event.path, object: receiver.object_id }
      if event.event == :call && event.method_id == :generate_token
        command = event.binding.local_variable_get(:cmd)
        row[:gadget] = event.binding.local_variable_get(:method)
        row[:command] = { encoding: command.encoding.name, characters: command.length, bytes: command.bytesize, base64: Base64.strict_encode64(command.b) }
      elsif event.event == :return && event.method_id == :generate_token
        row[:token] = event.return_value
      elsif event.event == :return && %i[check_appkey env_leak framework_leak].include?(event.method_id)
        row[:value] = event.return_value
      elsif event.event == :return && event.method_id == :send_request_cgi && event.return_value
        response = event.return_value
        artifact = format('owner-http-%04d.body', events.length)
        File.binwrite(File.join(directory, artifact), response.body.to_s.b)
        row[:response] = { code: response.code, body_artifact: artifact, body_sha256: Digest::SHA256.hexdigest(response.body.to_s.b) }
      elsif event.event == :return && event.return_value.is_a?(Msf::Exploit::CheckCode)
        row[:check] = { code: event.return_value.code, reason: event.return_value.reason }
      elsif event.event == :raise
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      end
      events << row
      File.open(File.join(directory, 'laraveltoken-owner-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@laraveltoken_events, events)
    framework.instance_variable_set(:@laraveltoken_trace, trace)
    trace.enable
    { installed: true }
  end
end
