# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'

# Observe the supported library reader and original PHP stage generator only.
module PhpSourceConsumerObservation
  def self.install(framework, directory)
    events = []
    source = File.realpath('modules/payloads/stages/php/meterpreter.rb')
    trace = TracePoint.new(:return) do |event|
      row = nil
      if event.self.equal?(MetasploitPayloads) && event.method_id == :read && event.binding.local_variable_get(:path_parts).flatten == %w[meterpreter meterpreter.php]
        value = event.return_value
        row = { kind: 'payload_read', source: event.path, path: MetasploitPayloads.path('meterpreter', 'meterpreter.php'), bytes: value.bytesize, sha256: Digest::SHA256.hexdigest(value) }
      elsif event.method_id == :generate_stage && event.path == source
        value = event.return_value
        row = { kind: 'stage_generated', source: event.path, payload: event.self.refname, bytes: value.bytesize, sha256: Digest::SHA256.hexdigest(value), debug_build: event.self.datastore['MeterpreterDebugBuild'], debug_logging: event.self.datastore['MeterpreterDebugLogging'] }
      end
      next unless row

      events << row
      File.open(File.join(directory, 'php-source-consumer-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@php_source_consumer_events, events)
    framework.instance_variable_set(:@php_source_consumer_trace, trace)
    trace.enable
    { installed: true }
  end
end
