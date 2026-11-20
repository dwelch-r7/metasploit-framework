# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'

# Observe the real CmdStager output and HTTP response without replacing methods.
module CactiDropperObservation
  def self.install(framework, directory)
    events = []
    trace = TracePoint.new(:call, :return) do |event|
      next unless %i[generate_payload_exe generate_cmdstager cmdstager_on_request_uri send_response].include?(event.method_id)

      owner = event.self
      next unless owner.is_a?(Msf::Exploit::Remote) && owner.fullname == CactiObservation::OWNER

      row = { event: event.event, method: event.method_id, object: owner.object_id, source: event.path }
      if event.event == :return && event.method_id == :generate_payload_exe
        bytes = event.return_value
        next unless bytes.is_a?(String) && bytes.start_with?("\x7fELF".b)

        digest = Digest::SHA256.hexdigest(bytes.b)
        name = 'cacti-dropper-' + digest + '.elf'
        File.binwrite(File.join(directory, name), bytes.b)
        row[:elf] = { sha256: digest, elf_class: bytes.getbyte(4), bytes: bytes.bytesize, file: name }
      elsif event.event == :return && event.method_id == :generate_cmdstager
        stager = owner.stager_instance
        path = stager.instance_variable_get(:@payload_path)
        path ||= File.join(stager.instance_variable_get(:@tempdir), stager.instance_variable_get(:@var_elf))
        row[:stager] = { flavor: owner.flavor, commands_base64: event.return_value.map { |command| Base64.strict_encode64(command.b) }, path: path }
      elsif event.event == :call && event.method_id == :send_response
        bytes = event.binding.local_variable_get(:body)
        next unless bytes.is_a?(String) && bytes.start_with?("\x7fELF".b)

        row[:served] = { sha256: Digest::SHA256.hexdigest(bytes.b), elf_class: bytes.getbyte(4), bytes: bytes.bytesize }
      elsif event.event == :call && event.method_id == :cmdstager_on_request_uri
        request = event.binding.local_variable_get(:request)
        row[:request] = { uri: request.uri, user_agent: request.headers['User-Agent'] }
      else
        next
      end
      events << row
      File.open(File.join(directory, 'cacti-dropper-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@cacti_dropper_events, events)
    framework.instance_variable_set(:@cacti_dropper_trace, trace)
    trace.enable
    { installed: true }
  end
end
