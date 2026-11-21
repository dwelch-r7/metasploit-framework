# frozen_string_literal: true

require 'base64'
require 'json'

# Capture the already supplied wrapper bytes without regenerating the payload.
module SudoChrootCallbackObservation
  def self.install(framework, directory)
    events = []
    trace = TracePoint.new(:call) do |event|
      next unless event.method_id == :upload_and_chmodx
      next unless event.self.is_a?(Msf::Module) && event.self.fullname == SudoChrootObservation::OWNER

      row = {
        object: event.self.object_id, path: event.binding.local_variable_get(:path),
        wrapper_base64: Base64.strict_encode64(event.binding.local_variable_get(:data).b)
      }
      events << row
      File.open(File.join(directory, 'sudo-callback-wrappers.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@sudo_callback_events, events)
    framework.instance_variable_set(:@sudo_callback_trace, trace)
    trace.enable
    { installed: true }
  end
end
