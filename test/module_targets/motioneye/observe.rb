# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'time'

# Trace real execution and delivery without replacing network or owner methods.
module MotioneyeObservation
  METHODS = %i[check exploit cleanup add_camera set_exploit trigger_exploit del_camera send_signed_request_cgi].freeze

  def self.install(framework, directory)
    owners = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).fetch('owners').values
    sources = owners.to_h { |owner| [File.expand_path('modules/' + owner.sub('exploit/', 'exploits/') + '.rb'), owner] }
    fetch_source = File.expand_path('lib/msf/core/payload/adapter/fetch.rb')
    events = []
    path = File.join(directory, 'owner-events.jsonl')
    File.write(path, '')
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless METHODS.include?(event.method_id) || event.method_id == :add_srv_entry

      source = File.expand_path(event.path)
      owner = sources[source]
      row = nil
      if owner && METHODS.include?(event.method_id)
        receiver = event.self
        row = {
          event: event.event, method: event.method_id, owner: owner, object: receiver.object_id,
          at: Time.now.utc.iso8601, payload: receiver.datastore['PAYLOAD'], target: receiver.datastore['TARGET']
        }
        if event.event == :return
          value = event.return_value
          if value.is_a?(Msf::Exploit::CheckCode)
            row[:check] = { code: value.code, reason: value.reason }
          elsif value.respond_to?(:code) && value.respond_to?(:body)
            row[:response] = { code: value.code, body_base64: Base64.strict_encode64(value.body.to_s.b) }
          elsif value.is_a?(Numeric)
            row[:value] = value
          end
        elsif event.event == :raise
          row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
        elsif event.method_id == :send_signed_request_cgi
          row[:options] = event.binding.local_variable_get(:opts)
        end
      elsif source == fetch_source && event.method_id == :add_srv_entry && event.event == :call
        data = event.binding.local_variable_get(:data)
        row = { event: 'delivery', family: 'fetch', sha256: Digest::SHA256.hexdigest(data), elf_class: data.getbyte(4) } if data.start_with?("\x7fELF".b)
      end
      next unless row

      events << row
      File.open(path, 'a') { |output| output.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@motioneye_events, events)
    framework.instance_variable_set(:@motioneye_trace, trace)
    trace.enable
    { installed: true, sources_sha256: sources.to_h { |source, owner| [owner, Digest::SHA256.file(source).hexdigest] }, events_path: path }
  end
end
