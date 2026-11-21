# frozen_string_literal: true

require 'base64'
require 'json'

# Trace actual owner calls and PHAR bytes without replacing implementation.
module IgnitionObservation
  OWNER = 'exploit/multi/php/ignition_laravel_debug_rce'

  def self.install(framework, directory)
    events = []
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless %i[check exploit find_log_file clear_log format_payload generate_phar post].include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.fullname == OWNER

      row = { event: event.event, method: event.method_id, source: event.path, object: receiver.object_id }
      if event.event == :call && event.method_id == :exploit
        row[:options] = %w[TARGET PAYLOAD RHOSTS RPORT AutoCheck LOGFILE].to_h { |name| [name, receiver.datastore[name]] }
      elsif event.event == :call && event.method_id == :generate_phar
        value = event.binding.local_variable_get(:pop)
        row[:serialized] = { encoding: value.encoding.name, characters: value.length, bytes: value.bytesize, base64: Base64.strict_encode64(value.b) }
      elsif event.event == :return && event.method_id == :generate_phar
        row[:phar_base64] = Base64.strict_encode64(event.return_value.b)
      elsif event.event == :return && event.method_id == :find_log_file
        row[:logfile] = event.return_value
      elsif event.event == :return && event.return_value.is_a?(Msf::Exploit::CheckCode)
        row[:check] = { code: event.return_value.code, reason: event.return_value.reason }
      elsif event.event == :raise
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      end
      events << row
      File.open(File.join(directory, 'ignition-owner-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@ignition_events, events)
    framework.instance_variable_set(:@ignition_trace, trace)
    trace.enable
    { installed: true }
  end
end
