# frozen_string_literal: true

require 'base64'
require 'json'
require 'net/http'

# Observe physical delivery before chat and the original FileDropper lifecycle.
module OllamaSessionObservation
  OWNER = 'exploit/linux/http/ollama_rce_cve_2024_37032'

  def self.read(observer, path)
    uri = URI(observer + '/file?' + URI.encode_www_form(path: path))
    response = Net::HTTP.start(uri.host, uri.port, nil, open_timeout: 3, read_timeout: 5) { |http| http.get(uri.request_uri) }
    raise IOError, 'Resident file observation failed' unless response.code == '200'

    JSON.parse(response.body)
  end

  def self.install(framework, directory, observer)
    events = []
    file_dropper = Msf::Exploit::FileDropper.instance_method(:on_new_session).source_location.first
    trace = TracePoint.new(:call, :return) do |event|
      next unless %i[trigger_rce on_new_session file_dropper_delete_file].include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.fullname == OWNER
      next if event.method_id == :on_new_session && event.path != file_dropper

      path = receiver.instance_variable_get(:@so_path)
      raise ArgumentError, 'Unexpected observed library path' unless path&.match?(%r{\A/tmp/module-target-ollama/owner/[A-Za-z]{8}\.so\z})

      row = { event: event.event, method: event.method_id, source: event.path, object: receiver.object_id, path: path, allow_no_cleanup: receiver.datastore['AllowNoCleanup'] }
      if event.method_id == :trigger_rce && event.event == :call
        row[:library] = read(observer, path)
        row[:preload] = read(observer, '/etc/ld.so.preload')
      elsif event.method_id == :on_new_session
        row[:session] = event.binding.local_variable_get(:session).sid
        row[:dropped_files] = receiver.instance_variable_get(:@dropped_files).dup
        row[:dropped_dirs] = receiver.instance_variable_get(:@dropped_dirs).dup
        row[:library] = read(observer, path) if event.event == :return
      elsif event.method_id == :file_dropper_delete_file
        row[:deleted_path] = event.binding.local_variable_get(:file)
        row[:result] = event.return_value if event.event == :return
      end
      events << row
      File.open(File.join(directory, 'ollama-session-lifecycle.jsonl'), 'a') { |output| output.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@ollama_lifecycle_events, events)
    framework.instance_variable_set(:@ollama_lifecycle_trace, trace)
    trace.enable
    { installed: true }
  end
end
