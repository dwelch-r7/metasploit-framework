# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'time'

# Observe actual owner, cleanup, HTTP and executable delivery calls passively.
module CraftTargetObservation
  METHODS = %i[check check_phpinfo upload_webshell exploit execute_command on_new_session cleanup].freeze

  def self.capture(directory, label, value)
    bytes = value.is_a?(String) ? value.b : JSON.generate(value).b
    return value if bytes.bytesize <= 16_384

    digest = Digest::SHA256.hexdigest(bytes)
    filename = label + '-' + digest + (value.is_a?(String) ? '.bytes' : '.json')
    File.binwrite(File.join(directory, filename), bytes)
    { size: bytes.bytesize, sha256: digest, capture_file: filename }
  end

  def self.install(framework, directory)
    owner = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).fetch('owner')
    source = File.expand_path('modules/' + owner.sub('exploit/', 'exploits/') + '.rb')
    cmdstager = File.expand_path('lib/msf/core/exploit/cmd_stager.rb')
    server = File.expand_path('lib/msf/core/exploit/remote/http_server.rb')
    fetch = File.expand_path('lib/msf/core/payload/adapter/fetch.rb')
    events = []
    path = File.join(directory, 'owner-events.jsonl')
    File.write(path, '')
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless METHODS.include?(event.method_id) || %i[send_request_cgi register_files_for_cleanup register_file_for_cleanup generate_cmdstager send_response add_srv_entry].include?(event.method_id)

      receiver = event.self
      location = File.expand_path(event.path)
      actual_owner = receiver.respond_to?(:fullname) && receiver.fullname == owner
      own = location == source && METHODS.include?(event.method_id)
      http = actual_owner && event.method_id == :send_request_cgi
      registration = actual_owner && %i[register_files_for_cleanup register_file_for_cleanup].include?(event.method_id)
      generation = actual_owner && location == cmdstager && event.method_id == :generate_cmdstager
      delivery = actual_owner && location == server && event.method_id == :send_response
      fetch_delivery = location == fetch && event.method_id == :add_srv_entry
      next unless own || http || registration || generation || delivery || fetch_delivery

      row = { event: event.event, method: event.method_id, at: Time.now.utc.iso8601, object: receiver.object_id }
      if event.event == :call
        row[:request] = capture(directory, 'http-request', event.binding.local_variable_get(:opts)) if http
        row[:command] = capture(directory, 'command', event.binding.local_variable_get(:cmd)) if own && event.method_id == :execute_command
        row[:registered_paths] = event.binding.local_variable_get(:files) if registration
        if delivery || fetch_delivery
          bytes = event.binding.local_variable_get(delivery ? :body : :data)
          row.merge!(event: 'delivery', sha256: Digest::SHA256.hexdigest(bytes), elf_class: bytes.getbyte(4)) if bytes.is_a?(String) && bytes.start_with?("\x7fELF".b)
        end
      elsif event.event == :return
        value = event.return_value
        if value.is_a?(Msf::Exploit::CheckCode)
          row[:check] = { code: value.code, reason: value.reason }
        elsif value.respond_to?(:code) && value.respond_to?(:body)
          body = value.body.to_s.b
          row[:response] = { code: value.code, size: body.bytesize, sha256: Digest::SHA256.hexdigest(body) }
          if body.bytesize > 16_384
            capture = 'http-body-' + Digest::SHA256.hexdigest(body) + '.response'
            File.binwrite(File.join(directory, capture), body)
            row[:response][:capture_file] = capture
          else
            row[:response][:body_base64] = Base64.strict_encode64(body)
          end
        elsif value == true || value == false || value.nil?
          row[:value] = value
        end
        if own && event.method_id == :upload_webshell
          config = receiver.instance_variable_get(:@config)
          name = receiver.instance_variable_get(:@webshell_name)
          row[:webshell_path] = File.join(config.fetch('document_root'), name) if config && config['document_root'] && name
        elsif generation
          bytes = receiver.exe
          row[:generated_exe] = { sha256: Digest::SHA256.hexdigest(bytes), elf_class: bytes.getbyte(4) } if bytes.is_a?(String)
          row[:generated_commands] = capture(directory, 'generated-commands', value)
        end
      elsif event.event == :raise
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      end
      events << row
      File.open(path, 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@craft_events, events)
    framework.instance_variable_set(:@craft_trace, trace)
    trace.enable
    { installed: true, source_sha256: Digest::SHA256.file(source).hexdigest, events_path: path }
  end
end
