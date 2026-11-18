# frozen_string_literal: true

require_relative '../druid_sessions/session_control'
require_relative '../saltstack_deployer/session_control'

# Passive source tracing and public handler APIs; no owner methods are replaced.
module MysqlUdfSessionControl
  def self.install(framework)
    observation = DruidSessionControl.install(framework)
    source = File.expand_path('modules/exploits/multi/mysql/mysql_udf_payload.rb')
    events = []
    trace = TracePoint.new(:call, :return) do |event|
      next unless File.expand_path(event.path) == source
      next unless %i[exploit login_and_get_sys_exec execute_command].include?(event.method_id)

      row = { event: event.event, method: event.method_id, object: event.self.object_id, session: event.self.datastore['SESSION'] }
      if event.event == :call && event.method_id == :execute_command
        row[:command_base64] = Base64.strict_encode64(event.binding.local_variable_get(:cmd))
        row[:executable_sha256] = Digest::SHA256.hexdigest(event.self.exe)
        row[:executable_header_hex] = event.self.exe.byteslice(0, 20).unpack1('H*')
      end
      if event.event == :return && event.method_id == :login_and_get_sys_exec
        row[:returned] = event.return_value
        row[:arch] = event.self.instance_variable_get(:@mysql_arch)
        row[:udf_available] = event.self.instance_variable_get(:@mysql_sys_exec_available)
      end
      events << row
    end
    framework.instance_variable_set(:@mysql_udf_events, events)
    framework.instance_variable_set(:@mysql_udf_trace, trace)
    trace.enable
    observation
  end
end
