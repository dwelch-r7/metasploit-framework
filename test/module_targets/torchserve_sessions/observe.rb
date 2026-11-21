# frozen_string_literal: true

require 'base64'
require 'json'

# Observe the original archive generator without changing delivery or payloads.
module TorchserveArchiveObservation
  def self.install(framework, directory)
    events = []
    deliveries = []
    trace = TracePoint.new(:call, :return) do |event|
      next unless %i[generate_mar send_response].include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.fullname == 'exploit/multi/http/torchserver_cve_2023_43654'

      row = { object: receiver.object_id, source: event.path }
      if event.method_id == :generate_mar && event.event == :return
        row[:archive_base64] = Base64.strict_encode64(event.return_value.b)
        events << row
        File.open(File.join(directory, 'torchserve-archives.jsonl'), 'a') { |output| output.puts(JSON.generate(row)) }
      elsif event.method_id == :send_response && event.event == :call
        body = event.binding.local_variable_get(:body)
        row[:body_base64] = Base64.strict_encode64(body.to_s.b)
        deliveries << row
        File.open(File.join(directory, 'torchserve-delivery.jsonl'), 'a') { |output| output.puts(JSON.generate(row)) }
      end
    end
    framework.instance_variable_set(:@torchserve_archives, events)
    framework.instance_variable_set(:@torchserve_archive_trace, trace)
    framework.instance_variable_set(:@torchserve_deliveries, deliveries)
    trace.enable
    { installed: true }
  end
end
