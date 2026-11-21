# frozen_string_literal: true

require 'base64'
require 'json'

# Trace the original module and Redis writer without replacing their behavior.
module RedisLuaObservation
  OWNER = 'exploit/linux/redis/redis_debian_sandbox_escape'
  METHODS = %i[check exploit execute_command do_os_exec do_popen send_redis_command].freeze

  def self.install(framework, directory)
    source = File.expand_path('../../../modules/exploits/linux/redis/redis_debian_sandbox_escape.rb', __dir__)
    events = []
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless event.self.is_a?(Msf::Exploit::Remote) && event.self.fullname == OWNER
      next unless event.event == :raise || METHODS.include?(event.method_id)

      row = { event: event.event, method: event.method_id, source: event.path, object: event.self.object_id }
      row[:owner_exploit_body] = true if event.event == :call && event.method_id == :exploit && File.expand_path(event.path) == source
      if event.event == :raise
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      elsif event.event == :call && %i[execute_command do_os_exec do_popen].include?(event.method_id)
        row[:command_base64] = Base64.strict_encode64(event.binding.local_variable_get(:cmd).b)
      elsif event.event == :return
        value = event.return_value
        row[:check] = { code: value.code, reason: value.reason } if value.is_a?(Msf::Exploit::CheckCode)
        row[:response_base64] = Base64.strict_encode64(value.b) if value.is_a?(String)
        row[:wire_base64] = Base64.strict_encode64(event.binding.local_variable_get(:exploit).b) if %i[do_os_exec do_popen].include?(event.method_id)
      end
      events << row
      File.open(File.join(directory, 'redis-lua-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@redis_lua_events, events)
    framework.instance_variable_set(:@redis_lua_trace, trace)
    trace.enable
    { installed: true }
  end
end
