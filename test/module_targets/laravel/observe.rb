# frozen_string_literal: true

require 'base64'
require 'json'

# Record the actual owner's crypto boundary without substituting its behavior.
module LaravelObservation
  def self.install(framework, directory, owner:, component:)
    events = []
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless %i[check exploit execute_command laravel_encrypt_session_cookie laravel_encrypt aes_encrypt].include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.fullname == owner

      row = { event: event.event, method: event.method_id, source: event.path, object: receiver.object_id }
      if event.event == :call && event.method_id == :exploit
        row[:options] = %w[TARGET PAYLOAD RHOSTS RPORT AutoCheck APP_KEY].to_h { |name| [name, receiver.datastore[name]] }
      elsif event.event == :call && event.method_id == :aes_encrypt
        value = event.binding.local_variable_get(:value)
        row[:plain] = { encoding: value.encoding.name, characters: value.length, bytes: value.bytesize, base64: Base64.strict_encode64(value.b) }
      elsif event.event == :call && event.method_id == :execute_command
        argument = receiver.method(:execute_command).parameters.first.last
        row[:cipher] = event.binding.local_variable_get(argument)
      elsif event.event == :return && event.return_value.is_a?(Msf::Exploit::CheckCode)
        row[:check] = { code: event.return_value.code, reason: event.return_value.reason }
      elsif event.event == :raise
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      end
      events << row
      File.open(File.join(directory, component + '-owner-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:"@#{component}_events", events)
    framework.instance_variable_set(:"@#{component}_trace", trace)
    trace.enable
    { installed: true }
  end
end
