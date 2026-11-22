# frozen_string_literal: true

require 'base64'
require 'json'

# Observe original source calls and their actual local sockets without replacing I/O.
module ProftpdCopyObservation
  OWNER = 'exploit/unix/ftp/proftpd_modcopy_exec'

  def self.install(framework, directory)
    events = []
    sockets = []
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless %i[check exploit].include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.fullname == OWNER

      row = { event: event.event, method: event.method_id, source: event.path, object: receiver.object_id }
      if event.event == :return && event.return_value.is_a?(Msf::Exploit::CheckCode)
        row[:check] = { code: event.return_value.code, reason: event.return_value.reason }
      elsif event.event == :raise
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      end
      if event.binding.local_variable_defined?(:sock)
        socket = event.binding.local_variable_get(:sock)
        if socket
          sockets << socket unless sockets.any? { |other| other.equal?(socket) }
          row[:socket] = { object: socket.object_id, closed: socket.closed? }
        end
      end
      events << row
      File.open(File.join(directory, 'proftpd-owner-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@proftpd_events, events)
    framework.instance_variable_set(:@proftpd_sockets, sockets)
    framework.instance_variable_set(:@proftpd_trace, trace)
    trace.enable
    { installed: true }
  end

  def self.sockets(framework, cleanup: false)
    framework.instance_variable_get(:@proftpd_sockets).map do |socket|
      row = { object: socket.object_id, closed: socket.closed? }
      socket.close if cleanup && !socket.closed?
      row
    end
  end
end
