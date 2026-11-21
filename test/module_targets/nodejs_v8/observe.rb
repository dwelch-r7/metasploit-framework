# frozen_string_literal: true

require 'base64'
require 'json'

# Passive source-bound observations; all protocol and payload methods stay original.
module NodejsV8Observation
  OWNER = 'exploit/multi/misc/nodejs_v8_debugger'
  METHODS = %i[check exploit make_eval_message].freeze

  def self.install(framework, directory)
    events = []
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless event.self.is_a?(Msf::Exploit::Remote) && event.self.fullname == OWNER
      next unless event.event == :raise || METHODS.include?(event.method_id)

      row = { event: event.event, method: event.method_id, source: event.path, object: event.self.object_id }
      if event.event == :raise
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      elsif event.event == :return
        value = event.return_value
        row[:check] = { code: value.code, reason: value.reason } if value.is_a?(Msf::Exploit::CheckCode)
        row[:message_base64] = Base64.strict_encode64(value.b) if event.method_id == :make_eval_message && value.is_a?(String)
      end
      events << row
      File.open(File.join(directory, 'nodejs-v8-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@nodejs_v8_events, events)
    framework.instance_variable_set(:@nodejs_v8_trace, trace)
    trace.enable
    { installed: true }
  end
end
