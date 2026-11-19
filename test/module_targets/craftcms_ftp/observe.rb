# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'time'

# Observe actual owner traffic and payload delivery without replacing handlers.
module CraftFtpObservation
  OWNER = 'exploit/linux/http/craftcms_ftp_template'
  REFNAME = OWNER.delete_prefix('exploit/').freeze
  COMMON_METHODS = %i[send_request_cgi send_request_raw cleanup passive_data_port_for_client establish_data_connection].freeze
  OWNER_METHODS = %i[initialize vulnerable_file_list get_payload send_ftp_response on_client_connect on_client_command_user on_client_command_pass on_client_command_cwd on_client_command_type on_client_command_size on_client_command_mdtm on_client_command_epsv on_client_command_retr on_client_command_quit on_client_command_unknown check trigger_http_request start_ftp_service exploit].freeze
  TRACE_METHODS = (COMMON_METHODS + OWNER_METHODS + [:add_srv_entry]).freeze

  def self.install(framework, directory)
    path = File.expand_path('modules/exploits/linux/http/craftcms_ftp_template.rb')
    fetch_source = File.expand_path('lib/msf/core/payload/adapter/fetch.rb')
    events = []
    output = File.join(directory, 'ftp-owner-events.jsonl')
    File.write(output, '')
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless TRACE_METHODS.include?(event.method_id)

      if event.method_id == :add_srv_entry
        next unless event.event == :call && File.expand_path(event.path) == fetch_source

        bytes = event.binding.local_variable_get(:data)
        if bytes.is_a?(String) && bytes.start_with?("\x7fELF".b)
          row = { event: 'delivery', family: 'fetch', sha256: Digest::SHA256.hexdigest(bytes), elf_class: bytes.getbyte(4), at: Time.now.utc.iso8601(6) }
          events << row
          File.open(output, 'a') { |file| file.puts(JSON.generate(row)) }
        end
        next
      end
      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.refname == REFNAME
      next unless COMMON_METHODS.include?(event.method_id) || File.expand_path(event.path) == path

      row = { event: event.event, method: event.method_id, at: Time.now.utc.iso8601(6), object: receiver.object_id }
      if event.event == :call
        row[:argument] = event.binding.local_variable_get(:arg) if event.binding.local_variable_defined?(:arg)
        row[:request] = event.binding.local_variable_get(:opts) if %i[send_request_cgi send_request_raw].include?(event.method_id)
      elsif event.event == :return
        value = event.return_value
        if value.is_a?(Msf::Exploit::CheckCode)
          row[:check] = { code: value.code, reason: value.reason }
        elsif value.respond_to?(:code) && value.respond_to?(:body)
          bytes = value.body.to_s.b
          filename = 'ftp-response-' + Digest::SHA256.hexdigest(bytes) + '.bytes'
          File.binwrite(File.join(directory, filename), bytes)
          row[:response] = { code: value.code, bytes: bytes.bytesize, sha256: Digest::SHA256.hexdigest(bytes), file: filename }
        elsif event.method_id == :get_payload && value.is_a?(String)
          row[:template_base64] = Base64.strict_encode64(value.b)
        end
      else
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      end
      events << row
      File.open(output, 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@craft_ftp_events, events)
    framework.instance_variable_set(:@craft_ftp_trace, trace)
    trace.enable
    { installed: true, owner_sha256: Digest::SHA256.file(path).hexdigest }
  end
end
