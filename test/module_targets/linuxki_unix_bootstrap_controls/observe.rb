# frozen_string_literal: true

require 'json'

# Capture staging/verification boundaries without replacing socket reads,
# payload generation, session registration or the target's program.
module LinuxkiBootstrapObservation
  def self.install(framework, directory)
    sockets = {}.compare_by_identity
    reads = {}
    events = []
    failures = []
    save = lambda do |row|
      events << row
      File.open(File.join(directory, 'bootstrap-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless %i[handle_connection get_once generate_stage bootstrap negotiate_tlv_encryption].include?(event.method_id)

      receiver = event.self
      if event.method_id == :handle_connection && event.path.end_with?('/payload/stager.rb')
        connection = event.binding.local_variable_get(:conn)
        if event.event == :call && sockets.length < 8
          sockets[connection] = { active: true }
          save.call(kind: 'stage-connection', socket: connection.object_id, payload: receiver.refname,
                    include_uuid: receiver.respond_to?(:include_send_uuid) && receiver.include_send_uuid)
        elsif event.event == :return && sockets[connection]
          sockets[connection][:active] = false
        end
      elsif event.method_id == :get_once && sockets.dig(receiver, :active)
        key = [receiver.object_id, Thread.current.object_id]
        if event.event == :call
          args = receiver.method(:get_once).parameters.filter_map do |_kind, name|
            [name, event.binding.local_variable_get(name)] if name && event.binding.local_variable_defined?(name)
          end.to_h
          reads[key] = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          save.call(kind: 'staging-read-call', socket: receiver.object_id, arguments: args)
        elsif event.event == :return
          value = event.return_value
          save.call(kind: 'staging-read-return', socket: receiver.object_id, bytes: value&.bytesize,
                    hex: value.is_a?(String) && value.bytesize <= 16 ? value.unpack1('H*') : nil,
                    elapsed: reads[key] ? Process.clock_gettime(Process::CLOCK_MONOTONIC) - reads[key] : nil)
        end
      elsif event.method_id == :generate_stage && event.event == :call && receiver.respond_to?(:refname) && receiver.refname == 'cmd/unix/php/meterpreter/reverse_tcp'
        options = event.binding.local_variable_defined?(:opts) ? event.binding.local_variable_get(:opts) : {}
        uuid = options[:uuid]
        save.call(kind: 'generate-stage', payload: receiver.refname, uuid_hex: uuid.respond_to?(:to_raw) ? uuid.to_raw.unpack1('H*') : nil)
      elsif event.method_id == :bootstrap && event.path.end_with?('/sessions/meterpreter.rb')
        if event.event == :call
          datastore = event.binding.local_variable_get(:datastore)
          save.call(kind: 'bootstrap-call', session: receiver.sid, comm_timeout: receiver.comm_timeout,
                    options: %w[AutoVerifySessionTimeout SessionCommunicationTimeout SessionExpirationTimeout SessionTlvLogging].to_h { |name| [name, datastore[name]] })
        elsif event.event == :return
          save.call(kind: 'bootstrap-return', session: receiver.sid, result_nil: event.return_value.nil?)
        end
      elsif event.method_id == :negotiate_tlv_encryption
        if event.event == :return
          value = event.return_value
          save.call(kind: 'negotiate-return', result_nil: value.nil?, result_keys: value.is_a?(Hash) ? value.keys : nil)
        elsif event.event == :raise
          save.call(kind: 'negotiate-error', type: event.raised_exception.class.name, message: event.raised_exception.message)
        end
      end
    rescue StandardError => e
      failures << { type: e.class.name, message: e.message }
      File.write(File.join(directory, 'bootstrap-observer-errors.json'), JSON.pretty_generate(failures))
    end
    framework.instance_variable_set(:@linuxki_bootstrap_trace, trace)
    framework.instance_variable_set(:@linuxki_bootstrap_events, events)
    trace.enable
    { installed: true, maximum_staging_connections: 8 }
  end
end
