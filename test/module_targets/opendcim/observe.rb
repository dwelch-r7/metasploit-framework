# frozen_string_literal: true

require 'base64'
require 'json'

# Original requests and SQL/command bytes; no owning method is replaced.
module OpenDcimObservation
  OWNER = 'exploit/linux/http/opendcim_install_sqli_rce'

  def self.install(framework, directory)
    events = []
    source = File.expand_path('../../../modules/exploits/linux/http/opendcim_install_sqli_rce.rb', __dir__)
    trace = TracePoint.new(:call, :return) do |event|
      next unless %i[check exploit send_request_cgi inject_sql backup_config poison_dot restore_config cleanup_config execute_command trigger_exec].include?(event.method_id)
      next unless event.self.is_a?(Msf::Exploit::Remote) && event.self.fullname == OWNER

      row = { event: event.event, method: event.method_id, source: event.path, object: event.self.object_id }
      row[:backup_table] = event.self.instance_variable_get(:@backup_table)
      row[:owner_exploit_body] = true if event.event == :call && event.method_id == :exploit && File.expand_path(event.path) == source
      if event.event == :call
        if event.method_id == :send_request_cgi
          options = event.binding.local_variable_get(:opts)
          row[:request] = { method: options['method'] || 'GET', uri: options['uri'], vars_post: options['vars_post'], vars_get: options['vars_get'] }
        elsif event.method_id == :inject_sql
          row[:sql] = { field: event.binding.local_variable_get(:field), base64: Base64.strict_encode64(event.binding.local_variable_get(:sql).b) }
        elsif event.method_id == :poison_dot
          row[:command_base64] = Base64.strict_encode64(event.binding.local_variable_get(:dot_value).b)
        end
      else
        result = event.return_value
        if result.is_a?(Msf::Exploit::CheckCode)
          row[:check] = { code: result.code, reason: result.reason }
        elsif event.method_id == :send_request_cgi && result
          row[:response] = { code: result.code, body_base64: Base64.strict_encode64(result.body.to_s.b) }
        elsif %i[inject_sql backup_config poison_dot restore_config].include?(event.method_id)
          row[:result] = result
        end
      end
      events << row
      File.open(File.join(directory, 'opendcim-events.jsonl'), 'a') { |output| output.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@opendcim_events, events)
    framework.instance_variable_set(:@opendcim_trace, trace)
    trace.enable
    { installed: true }
  end
end
