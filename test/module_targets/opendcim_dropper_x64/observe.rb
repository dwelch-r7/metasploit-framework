# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'

# Observe original executable/stager returns without replacing generation.
module OpenDcimDropperObservation
  def self.paths(stager)
    prefix = stager.instance_variable_get(:@tempdir)
    %i[@var_elf @var_decoded @var_encoded].to_h do |name|
      basename = stager.instance_variable_get(name)
      [name.to_s.delete_prefix('@var_'), prefix.is_a?(String) && basename.is_a?(String) ? prefix + basename : nil]
    end.compact
  end

  def self.install(framework, directory)
    events = []
    trace = TracePoint.new(:return) do |event|
      next unless %i[generate_payload_exe generate_cmdstager].include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.fullname == 'exploit/linux/http/opendcim_install_sqli_rce'

      value = event.return_value
      row = { event: event.event, method: event.method_id, source: event.path, object: receiver.object_id }
      if event.method_id == :generate_payload_exe && value
        row.merge!(executable_base64: Base64.strict_encode64(value.b), sha256: Digest::SHA256.hexdigest(value), payload: receiver.payload_instance.refname, fork: receiver.payload_instance.datastore['MeterpreterTryToFork'])
      elsif event.method_id == :generate_cmdstager && value
        row.merge!(commands: value.dup, flavor: receiver.flavor, executable_sha256: Digest::SHA256.hexdigest(receiver.exe), paths: paths(receiver.stager_instance))
      end
      events << row
      File.open(File.join(directory, 'opendcim-dropper-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@opendcim_dropper_events, events)
    framework.instance_variable_set(:@opendcim_dropper_trace, trace)
    trace.enable
    { installed: true }
  end
end
