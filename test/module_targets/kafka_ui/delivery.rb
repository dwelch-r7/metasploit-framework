# frozen_string_literal: true

require 'digest'
require 'json'
require 'time'

# Observe payload bytes already registered by the real fetch adapter.
module KafkaPayloadDelivery
  def self.install(framework, directory)
    source = File.expand_path('lib/msf/core/payload/adapter/fetch.rb')
    events = []
    trace = TracePoint.new(:call) do |event|
      next unless event.method_id == :add_srv_entry && File.expand_path(event.path) == source

      bytes = event.binding.local_variable_get(:data)
      next unless bytes.is_a?(String) && bytes.start_with?("\x7fELF".b)

      digest = Digest::SHA256.hexdigest(bytes.b)
      filename = 'kafka-ui-fetch-' + digest + '.elf'
      File.binwrite(File.join(directory, filename), bytes.b)
      row = { sha256: digest, elf_class: bytes.getbyte(4), bytes: bytes.bytesize, file: filename, at: Time.now.utc.iso8601(6) }
      events << row
      File.open(File.join(directory, 'kafka-ui-delivery.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@kafka_payload_deliveries, events)
    framework.instance_variable_set(:@kafka_delivery_trace, trace)
    trace.enable
    { source_sha256: Digest::SHA256.file(source).hexdigest }
  end
end
