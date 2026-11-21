# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'

# Capture real executable and stager returns before their normal execution.
module LuceeDropperObservation
  def self.install(framework, directory)
    events = []
    trace = TracePoint.new(:return) do |event|
      next unless %i[generate_payload_exe generate_cmdstager].include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.fullname == 'exploit/linux/http/lucee_admin_imgprocess_file_write'

      value = event.return_value
      row = { event: event.event, method: event.method_id, source: event.path, object: receiver.object_id }
      if event.method_id == :generate_payload_exe && value
        row.merge!(executable_base64: Base64.strict_encode64(value.b), sha256: Digest::SHA256.hexdigest(value), bytes: value.bytesize, payload: receiver.payload_instance.refname, fork: receiver.payload_instance.datastore['MeterpreterTryToFork'])
      elsif event.method_id == :generate_cmdstager && value
        stager = receiver.stager_instance
        prefix = stager.instance_variable_get(:@tempdir)
        decoded = stager.instance_variable_get(:@var_decoded)
        encoded = stager.instance_variable_get(:@var_encoded)
        row.merge!(commands: value.dup, flavor: receiver.flavor, executable_sha256: Digest::SHA256.hexdigest(receiver.exe))
        row.merge!(decoded_path: prefix + decoded, encoded_path: prefix + encoded) if [prefix, decoded, encoded].all? { |item| item.is_a?(String) }
      end
      events << row
      File.open(File.join(directory, 'lucee-dropper-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@lucee_dropper_events, events)
    framework.instance_variable_set(:@lucee_dropper_trace, trace)
    trace.enable
    { installed: true }
  end
end
