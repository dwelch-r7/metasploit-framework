# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'time'

# Observe real owner calls and wire responses without replacing their behavior.
module CraftAssetObservation
  OWNER = 'exploit/linux/http/craftcms_preauth_rce_cve_2025_32432'
  REFNAME = OWNER.delete_prefix('exploit/').freeze
  METHODS = %i[initialize check exploit execute_via_session fetch_cookies_and_csrf extract_csrf_token leak_session_path send_transform send_request_cgi cleanup add_srv_entry].freeze

  def self.install(framework, directory)
    source = File.expand_path('modules/exploits/linux/http/craftcms_preauth_rce_cve_2025_32432.rb')
    fetch_source = File.expand_path('lib/msf/core/payload/adapter/fetch.rb')
    events = []
    path = File.join(directory, 'asset-owner-events.jsonl')
    File.write(path, '')
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless METHODS.include?(event.method_id)

      if event.method_id == :add_srv_entry
        next unless event.event == :call && File.expand_path(event.path) == fetch_source

        bytes = event.binding.local_variable_get(:data)
        if bytes.is_a?(String) && bytes.start_with?("\x7fELF".b)
          row = { event: 'delivery', family: 'fetch', sha256: Digest::SHA256.hexdigest(bytes), elf_class: bytes.getbyte(4), at: Time.now.utc.iso8601(6) }
          events << row
          File.open(path, 'a') { |file| file.puts(JSON.generate(row)) }
        end
        next
      end
      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.refname == REFNAME
      next unless File.expand_path(event.path) == source || %i[send_request_cgi cleanup].include?(event.method_id)

      row = { event: event.event, method: event.method_id, at: Time.now.utc.iso8601(6), object: receiver.object_id }
      if event.event == :call
        row[:request] = event.binding.local_variable_get(:opts) if event.method_id == :send_request_cgi
        row[:php_code_base64] = Base64.strict_encode64(event.binding.local_variable_get(:payload).b) if event.method_id == :execute_via_session
      elsif event.event == :return
        value = event.return_value
        if value.is_a?(Msf::Exploit::CheckCode)
          row[:check] = { code: value.code, reason: value.reason }
        elsif value.respond_to?(:body) && value.respond_to?(:code)
          bytes = value.body.to_s.b
          filename = 'asset-response-' + Digest::SHA256.hexdigest(bytes) + '.bytes'
          File.binwrite(File.join(directory, filename), bytes)
          row[:response] = { code: value.code, bytes: bytes.bytesize, sha256: Digest::SHA256.hexdigest(bytes), file: filename }
        elsif event.method_id == :fetch_cookies_and_csrf && value.is_a?(Array)
          row[:session] = { sid: value[0], csrf_sha256: Digest::SHA256.hexdigest(value[1].to_s), parameter: value[2] }
        elsif %i[leak_session_path extract_csrf_token].include?(event.method_id)
          row[:value] = event.method_id == :extract_csrf_token ? { present: !value.to_s.empty?, sha256: Digest::SHA256.hexdigest(value.to_s) } : value
        end
      else
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      end
      events << row
      File.open(path, 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@craft_asset_events, events)
    framework.instance_variable_set(:@craft_asset_trace, trace)
    trace.enable
    { installed: true, source_sha256: Digest::SHA256.file(source).hexdigest }
  end
end
