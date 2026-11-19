# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'time'

# Capture actual owner calls and socket buffers without replacing target behavior.
module ApisixObservation
  OWNER = 'exploit/multi/http/apache_apisix_api_default_token_rce'
  REFNAME = OWNER.delete_prefix('exploit/').freeze
  METHODS = %i[check exploit add_route filter_func_exec batch_request batch_request_enabled? cleanup send_request_cgi].freeze

  def self.install(framework, directory)
    source = File.expand_path('modules/exploits/multi/http/apache_apisix_api_default_token_rce.rb')
    stream = File.expand_path(Rex::IO::Stream.instance_method(:put).source_location.first)
    events = []
    path = File.join(directory, 'apisix-owner-events.jsonl')
    File.write(path, '')
    append = lambda do |row|
      events << row
      File.open(path, 'a') { |file| file.puts(JSON.generate(row)) }
    end
    trace = TracePoint.new(:call, :return, :raise) do |event|
      if event.event == :call && event.method_id == :put && File.expand_path(event.path) == stream && caller_locations.any? { |location| location.path && File.expand_path(location.path) == source }
        bytes = event.binding.local_variable_get(:buf)
        if bytes.is_a?(String) && bytes.match?(/\A(?:GET|POST|PUT|DELETE) /)
          name = 'apisix-wire-' + Digest::SHA256.hexdigest(bytes.b) + '.http'
          File.binwrite(File.join(directory, name), bytes.b)
          append.call(event: 'wire', file: name, sha256: Digest::SHA256.hexdigest(bytes.b), bytes: bytes.bytesize)
        end
        next
      end
      next unless METHODS.include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.refname == REFNAME

      row = { event: event.event, method: event.method_id, object: receiver.object_id, source: event.path, at: Time.now.utc.iso8601(6) }
      if event.event == :call
        row[:request] = event.binding.local_variable_get(:opts) if event.method_id == :send_request_cgi
        row[:datastore_command_base64] = Base64.strict_encode64(receiver.datastore['CMD'].to_s.b) if event.method_id == :exploit
      elsif event.event == :return
        value = event.return_value
        if value.is_a?(Msf::Exploit::CheckCode)
          row[:check] = { code: value.code, reason: value.reason }
        elsif value.respond_to?(:code) && value.respond_to?(:body)
          bytes = value.body.to_s.b
          name = 'apisix-response-' + Digest::SHA256.hexdigest(bytes) + '.bytes'
          File.binwrite(File.join(directory, name), bytes)
          row[:response] = { code: value.code, file: name, sha256: Digest::SHA256.hexdigest(bytes) }
        end
        if %i[add_route filter_func_exec].include?(event.method_id) && event.binding.local_variable_defined?(:stub)
          row[:lua_base64] = Base64.strict_encode64(event.binding.local_variable_get(:stub).b)
        end
        if %i[add_route filter_func_exec].include?(event.method_id) && receiver.payload.is_a?(Msf::EncodedPayload)
          # Both readers return the already generated objects; no payload is regenerated.
          row[:payload_base64] = Base64.strict_encode64(receiver.payload.encoded.b)
        end
      else
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      end
      append.call(row)
    end
    framework.instance_variable_set(:@apisix_events, events)
    framework.instance_variable_set(:@apisix_trace, trace)
    trace.enable
    { installed: true, source_sha256: Digest::SHA256.file(source).hexdigest, stream_sha256: Digest::SHA256.file(stream).hexdigest }
  end
end
