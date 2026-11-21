# frozen_string_literal: true

require 'base64'
require 'json'

# Original calls, returns and failures; no module method is replaced.
module DizquetvObservation
  OWNER = 'exploit/multi/http/dizquetv_rce'

  def self.install(framework, directory)
    events = []
    source = File.expand_path('../../../modules/exploits/multi/http/dizquetv_rce.rb', __dir__)
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless event.self.is_a?(Msf::Exploit::Remote) && event.self.fullname == OWNER
      next unless event.event == :raise || %i[check exploit set_ffmpeg_path trigger_execution restore_ffmpeg_settings retrieve_output upload_script send_request_cgi].include?(event.method_id)

      row = { event: event.event, method: event.method_id, source: event.path, object: event.self.object_id }
      row[:owner_exploit_body] = true if event.event == :call && event.method_id == :exploit && File.expand_path(event.path) == source
      if event.event == :raise
        error = event.raised_exception
        row[:error] = { type: error.class.name, message: error.message }
        row[:error][:reason] = event.self.fail_reason if error.is_a?(Msf::Exploit::Failed)
      elsif event.event == :call && event.method_id == :send_request_cgi
        options = event.binding.local_variable_get(:opts)
        row[:request] = { method: options['method'] || 'GET', uri: options['uri'], data_base64: options['data'] && Base64.strict_encode64(options['data'].b) }
      elsif event.event == :call && event.method_id == :set_ffmpeg_path
        row[:command_base64] = Base64.strict_encode64(event.self.instance_variable_get(:@cmd).b)
      elsif event.event == :return
        result = event.return_value
        row[:check] = { code: result.code, reason: result.reason } if result.is_a?(Msf::Exploit::CheckCode)
        row[:response] = { code: result.code, body_base64: Base64.strict_encode64(result.body.to_s.b) } if event.method_id == :send_request_cgi && result
        if event.method_id == :trigger_execution
          output = event.self.instance_variable_get(:@linux_output)
          row[:output_base64] = Base64.strict_encode64(output.b) if output
        elsif event.method_id == :restore_ffmpeg_settings
          row[:original_settings_cleared] = event.self.instance_variable_get(:@original_settings).nil?
        end
      end
      events << row
      File.open(File.join(directory, 'dizquetv-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@dizquetv_events, events)
    framework.instance_variable_set(:@dizquetv_trace, trace)
    trace.enable
    { installed: true }
  end
end
