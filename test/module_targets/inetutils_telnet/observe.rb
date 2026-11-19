# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'time'

# Observe the execution replicant without changing the owner's network methods.
module InetutilsObservation
  OWNER = 'exploit/linux/telnet/gnu_inetutils_auth_bypass'
  METHODS = %i[exploit recv_telnet add_srv_entry].freeze

  def self.install(framework, directory)
    source = File.expand_path('modules/exploits/linux/telnet/gnu_inetutils_auth_bypass.rb')
    events = []
    fetch_source = File.expand_path('lib/msf/core/payload/adapter/fetch.rb')
    path = File.join(directory, 'owner-events.jsonl')
    File.write(path, '')
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless METHODS.include?(event.method_id)

      if File.expand_path(event.path) == fetch_source && event.event == :call && event.method_id == :add_srv_entry
        data = event.binding.local_variable_get(:data)
        if data.start_with?("\x7fELF".b)
          row = {
            event: 'delivery', method: event.method_id, sha256: Digest::SHA256.hexdigest(data),
            bytes: data.bytesize, elf_class: data.getbyte(4), uri: event.binding.local_variable_get(:uri)
          }
          events << row
          File.open(path, 'a') { |output| output.puts(JSON.generate(row)) }
        end
        next
      end
      next unless File.expand_path(event.path) == source
      next unless %i[exploit recv_telnet].include?(event.method_id)

      receiver = event.self
      row = {
        event: event.event, method: event.method_id, object: receiver.object_id, at: Time.now.utc.iso8601,
        user: receiver.datastore['USERNAME'], payload: receiver.datastore['PAYLOAD'],
        command_base64: receiver.datastore['CMD'] && Base64.strict_encode64(receiver.datastore['CMD'].b),
        receive_count: receiver.instance_variable_get(:@client_sends)
      }
      if event.event == :return && event.return_value.is_a?(String)
        row[:returned_bytes_base64] = Base64.strict_encode64(event.return_value.b)
      elsif event.event == :raise
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      end
      events << row
      File.open(path, 'a') { |output| output.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@inetutils_events, events)
    framework.instance_variable_set(:@inetutils_trace, trace)
    trace.enable
    { installed: true, owner: OWNER, owner_sha256: Digest::SHA256.file(source).hexdigest, events_path: path }
  end
end
