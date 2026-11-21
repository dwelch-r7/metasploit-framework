# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'

# Trace the actual module and HTTP client without replacing either producer.
module CalibreObservation
  OWNER = 'exploit/multi/misc/calibre_exec'

  def self.install(framework, directory)
    events = []
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless %i[check exploit execute_command exec_calibre send_request_cgi].include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.fullname == OWNER

      row = { event: event.event, method: event.method_id, source: event.path, object: receiver.object_id }
      if event.event == :call && %i[execute_command exec_calibre].include?(event.method_id)
        command = event.binding.local_variable_get(:cmd)
        row[:command] = { encoding: command.encoding.name, base64: Base64.strict_encode64(command.b) }
      elsif event.event == :call && event.method_id == :send_request_cgi
        options = event.binding.local_variable_get(:opts)
        if options['data']
          artifact = format('owner-request-%04d.body', events.length)
          File.binwrite(File.join(directory, artifact), options.fetch('data').b)
          row[:request] = { method: options['method'], uri: options['uri'], body_artifact: artifact, body_sha256: Digest::SHA256.hexdigest(options.fetch('data').b) }
        end
      elsif event.event == :return && event.method_id == :send_request_cgi && event.return_value
        response = event.return_value
        artifact = format('owner-response-%04d.body', events.length)
        File.binwrite(File.join(directory, artifact), response.body.to_s.b)
        row[:response] = { code: response.code, body_artifact: artifact, body_sha256: Digest::SHA256.hexdigest(response.body.to_s.b) }
      elsif event.event == :return && event.return_value.is_a?(Msf::Exploit::CheckCode)
        row[:check] = { code: event.return_value.code, reason: event.return_value.reason }
      elsif event.event == :raise
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      end
      events << row
      File.open(File.join(directory, 'calibre-owner-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@calibre_events, events)
    framework.instance_variable_set(:@calibre_trace, trace)
    trace.enable
    { installed: true }
  end
end
