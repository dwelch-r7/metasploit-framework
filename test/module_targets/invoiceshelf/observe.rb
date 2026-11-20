# frozen_string_literal: true

require 'base64'
require 'json'

# Record the actual owner's crypto boundary without substituting its behavior.
module InvoiceShelfObservation
  OWNER = 'exploit/linux/http/invoiceshelf_unauth_rce_cve_2024_55556'

  def self.install(framework, directory)
    events = []
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless %i[check exploit execute_command laravel_encrypt_session_cookie aes_encrypt].include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.fullname == OWNER

      row = { event: event.event, method: event.method_id, source: event.path, object: receiver.object_id }
      if event.event == :call && event.method_id == :exploit
        row[:options] = %w[TARGET PAYLOAD RHOSTS RPORT AutoCheck APP_KEY].to_h { |name| [name, receiver.datastore[name]] }
      elsif event.event == :call && event.method_id == :aes_encrypt
        value = event.binding.local_variable_get(:value)
        row[:plain] = { encoding: value.encoding.name, characters: value.length, bytes: value.bytesize, base64: Base64.strict_encode64(value.b) }
      elsif event.event == :call && event.method_id == :execute_command
        row[:cipher] = event.binding.local_variable_get(:laravel_cookie_cipher)
      elsif event.event == :return && event.return_value.is_a?(Msf::Exploit::CheckCode)
        row[:check] = { code: event.return_value.code, reason: event.return_value.reason }
      elsif event.event == :raise
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      end
      events << row
      File.open(File.join(directory, 'invoiceshelf-owner-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@invoiceshelf_events, events)
    framework.instance_variable_set(:@invoiceshelf_trace, trace)
    trace.enable
    { installed: true }
  end
end
