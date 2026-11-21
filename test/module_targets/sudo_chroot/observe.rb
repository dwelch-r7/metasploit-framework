# frozen_string_literal: true

require 'base64'
require 'json'

# Passive original entry-point, file-operation and check return observations.
module SudoChrootObservation
  OWNER = 'exploit/linux/local/sudo_chroot_cve_2025_32463'
  METHODS = %i[check exploit get_version live_compile? file? cd pwd mkdir write_file copy_file upload_and_chmodx upload_and_compile register_files_for_cleanup register_dirs_for_cleanup cleanup].freeze

  def self.install(framework, directory)
    events = []
    trace = TracePoint.new(:call, :return, :raise) do |event|
      next unless event.self.is_a?(Msf::Module) && event.self.fullname == OWNER
      next unless event.event == :raise || METHODS.include?(event.method_id)
      next if event.event == :raise && !event.path.end_with?('/sudo_chroot_cve_2025_32463.rb')

      row = { event: event.event, method: event.method_id, source: event.path, object: event.self.object_id }
      if event.event == :raise
        row[:error] = { type: event.raised_exception.class.name, message: event.raised_exception.message }
      else
        row[:locals] = %i[path temp_dir payload_file base_dir lib_filename existing_shell].filter_map do |name|
          next unless event.binding.local_variable_defined?(name)

          value = event.binding.local_variable_get(name)
          [name, Base64.strict_encode64(value.b)] if value.is_a?(String)
        end.to_h
        if event.event == :return
          value = event.return_value
          if value.is_a?(Msf::Exploit::CheckCode)
            row[:check] = { code: value.code, reason: value.reason }
          elsif value.is_a?(String)
            row[:value_base64] = Base64.strict_encode64(value.b)
          elsif value.nil? || value == true || value == false
            row[:value] = value
          end
        end
      end
      events << row
      File.open(File.join(directory, 'sudo-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@sudo_events, events)
    framework.instance_variable_set(:@sudo_trace, trace)
    trace.enable
    { installed: true }
  end

  def self.cwd(framework, identifier)
    session = framework.sessions.fetch(identifier)
    session.type == 'meterpreter' ? session.fs.dir.getwd : session.shell_command_token('pwd').strip
  rescue Rex::Post::Meterpreter::RequestError => e
    { operation: 'getwd', error: e.class.name, message: e.message }
  end

  def self.restore_cwd(framework, identifier)
    session = framework.sessions.fetch(identifier)
    if session.type == 'meterpreter'
      session.fs.dir.chdir('/home/lab')
    else
      session.shell_command_token('cd /home/lab')
    end
    true
  end
end
