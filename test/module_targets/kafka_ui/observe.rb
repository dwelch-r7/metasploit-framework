# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'time'

# Observe real source calls and responses without replacing their behavior.
module KafkaUiObservation
  OWNER = 'exploit/linux/http/kafka_ui_unauth_rce_cve_2023_52251'
  REFNAME = OWNER.delete_prefix('exploit/').freeze
  METHODS = %i[check vuln_version? get_cluster create_topic produce_message delete_topic execute_command exploit cleanup send_request_cgi].freeze

  def self.install(framework, directory)
    source = File.expand_path('modules/exploits/linux/http/kafka_ui_unauth_rce_cve_2023_52251.rb')
    stream_source = File.expand_path(Rex::IO::Stream.instance_method(:put).source_location.first)
    events = []
    path = File.join(directory, 'kafka-ui-owner-events.jsonl')
    File.write(path, '')
    trace = TracePoint.new(:call, :return, :raise) do |event|
      if event.event == :call && event.method_id == :put && File.expand_path(event.path) == stream_source && caller_locations.any? { |location| location.path && File.expand_path(location.path) == source }
        bytes = event.binding.local_variable_get(:buf)
        if bytes.is_a?(String) && bytes.match?(/\A(?:GET|POST|DELETE) /)
          filename = 'kafka-ui-wire-' + Digest::SHA256.hexdigest(bytes.b) + '.http'
          File.binwrite(File.join(directory, filename), bytes.b)
          row = { event: 'wire', method: 'put', file: filename, sha256: Digest::SHA256.hexdigest(bytes.b), bytes: bytes.bytesize, at: Time.now.utc.iso8601(6) }
          events << row
          File.open(path, 'a') { |file| file.puts(JSON.generate(row)) }
        end
        next
      end
      next unless METHODS.include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.refname == REFNAME
      next unless File.expand_path(event.path) == source || %i[cleanup send_request_cgi].include?(event.method_id)

      row = { event: event.event, method: event.method_id, at: Time.now.utc.iso8601(6), object: receiver.object_id }
      if event.event == :call
        row[:request] = event.binding.local_variable_get(:opts) if event.method_id == :send_request_cgi
        row[:command_base64] = Base64.strict_encode64(event.binding.local_variable_get(:cmd).b) if event.method_id == :execute_command
        row[:datastore_command_base64] = Base64.strict_encode64(receiver.datastore['CMD'].to_s.b) if event.method_id == :exploit
      elsif event.event == :return
        value = event.return_value
        if value.is_a?(Msf::Exploit::CheckCode)
          row[:check] = { code: value.code, reason: value.reason }
        elsif value.respond_to?(:body) && value.respond_to?(:code)
          bytes = value.body.to_s.b
          filename = 'kafka-ui-response-' + Digest::SHA256.hexdigest(bytes) + '.bytes'
          File.binwrite(File.join(directory, filename), bytes)
          row[:response] = { code: value.code, sha256: Digest::SHA256.hexdigest(bytes), file: filename }
        elsif %i[get_cluster create_topic delete_topic produce_message vuln_version?].include?(event.method_id)
          row[:value] = value
        end
      else
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      end
      events << row
      File.open(path, 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@kafka_ui_events, events)
    framework.instance_variable_set(:@kafka_ui_trace, trace)
    trace.enable
    { source_sha256: Digest::SHA256.file(source).hexdigest, wire_stream_source: stream_source, wire_stream_sha256: Digest::SHA256.file(stream_source).hexdigest }
  end
end
