# frozen_string_literal: true

require 'base64'
require 'json'

# Passive original serializer, credential-result, data-reader and report events.
module RedisProtocolObservation
  OWNERS = %w[auxiliary/scanner/redis/redis_server auxiliary/scanner/redis/redis_login auxiliary/gather/redis_extractor auxiliary/scanner/redis/file_upload exploit/linux/redis/redis_debian_sandbox_escape].freeze
  METHODS = %i[redis_proto send_redis_command value_for_key check_host check report_service attempt_login authenticate authenticate_pre_v6].freeze

  def self.normalize(value)
    case value
    when String
      { kind: 'string', base64: Base64.strict_encode64(value.b) }
    when Array
      { kind: 'array', values: value.map { |item| normalize(item) } }
    when Hash
      { kind: 'hash', pairs: value.map { |key, item| [normalize(key), normalize(item)] }.sort_by { |row| row.first.fetch(:base64) } }
    when nil
      { kind: 'nil' }
    end
  end

  def self.install(framework, directory)
    events = []
    trace = TracePoint.new(:call, :return, :raise) do |event|
      owner = event.self.fullname if event.self.is_a?(Msf::Module)
      scanner = event.self.is_a?(Metasploit::Framework::LoginScanner::Redis)
      next unless OWNERS.include?(owner) || scanner
      next unless event.event == :raise || METHODS.include?(event.method_id)

      row = { event: event.event, method: event.method_id, source: event.path, owner: owner, object: event.self.object_id }
      if event.event == :raise
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      elsif event.method_id == :value_for_key
        row[:key_base64] = Base64.strict_encode64(event.binding.local_variable_get(:key).b)
        row[:value] = normalize(event.return_value) if event.event == :return
      elsif event.method_id == :redis_proto
        parts = event.binding.local_variable_get(:command_parts)
        row[:arguments] = parts.map { |part| { base64: Base64.strict_encode64(part.b), encoding: part.encoding.name } }
        row[:wire_base64] = Base64.strict_encode64(event.return_value.b) if event.event == :return && event.return_value
      elsif event.method_id == :attempt_login && event.event == :return
        result = event.return_value
        row[:login] = { status: result.status, proof: result.proof&.to_s, password_encoding: result.credential.private.encoding.name }
      elsif %i[authenticate authenticate_pre_v6].include?(event.method_id) && event.event == :return && event.return_value
        row[:authentication_response_base64] = Base64.strict_encode64(event.return_value.b)
      elsif event.method_id == :report_service && event.event == :call
        row[:service] = event.binding.local_variable_get(:opts)
      elsif event.event == :return && event.return_value.is_a?(Msf::Exploit::CheckCode)
        row[:check] = { code: event.return_value.code, reason: event.return_value.reason }
      end
      events << row
      File.open(File.join(directory, 'redis-protocol-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@redis_protocol_events, events)
    framework.instance_variable_set(:@redis_protocol_trace, trace)
    trace.enable
    { installed: true }
  end
end
