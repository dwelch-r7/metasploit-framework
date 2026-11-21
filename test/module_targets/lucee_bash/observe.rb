# frozen_string_literal: true

require 'base64'
require 'json'
require 'open3'

# Observe physical source before execution and the unmodified FileDropper path.
module LuceeLifecycleObservation
  OWNER = 'exploit/linux/http/lucee_admin_imgprocess_file_write'
  DIRECTORY = '/opt/lucee/web/temp/admin-ext-thumbnails/__/'

  def self.command(compose, *arguments)
    output, error, status = Open3.capture3(*compose, 'exec', '-T', 'target', *arguments)
    { argv: arguments, exit: status.exitstatus, stdout_base64: Base64.strict_encode64(output.b), stderr: error }
  end

  def self.physical(compose, path)
    exists = command(compose, 'test', '-e', path)
    value = { path: path, exists: exists.fetch(:exit).zero?, commands: [exists] }
    if value.fetch(:exists)
      value[:content] = command(compose, 'cat', '--', path)
      value[:uid] = command(compose, 'stat', '-c', '%u', '--', path)
    end
    value
  end

  def self.install(framework, directory, compose)
    events = []
    methods = %i[write_cfml_stub on_new_session file_dropper_delete_file file_dropper_delete_dir]
    file_dropper = Msf::Exploit::FileDropper.instance_method(:on_new_session).source_location.first
    trace = TracePoint.new(:call, :return) do |event|
      next unless methods.include?(event.method_id)

      receiver = event.self
      next unless receiver.is_a?(Msf::Exploit::Remote) && receiver.fullname == OWNER
      next if event.method_id == :on_new_session && event.path != file_dropper

      row = { event: event.event, method: event.method_id, source: event.path, object: receiver.object_id, allow_no_cleanup: receiver.datastore['AllowNoCleanup'] }
      filename = receiver.instance_variable_get(:@cfml_filename)
      if filename
        raise ArgumentError, 'Unexpected observed Lucee CFML filename' unless filename.match?(/\A[A-Za-z0-9]{8,16}\.cfm\z/)

        row[:stub_path] = '/opt/lucee/web/context/' + filename
      end
      if event.method_id == :write_cfml_stub && event.event == :return && event.return_value
        row[:physical] = physical(compose, row.fetch(:stub_path))
        row[:directory] = command(compose, 'test', '-d', DIRECTORY)
      elsif event.method_id == :on_new_session
        session = event.binding.local_variable_get(:session)
        row[:session] = session.sid
        row[:dropped_files] = receiver.instance_variable_get(:@dropped_files).dup
        row[:dropped_dirs] = receiver.instance_variable_get(:@dropped_dirs).dup
        if event.event == :return
          row[:physical] = physical(compose, row.fetch(:stub_path))
          row[:directory] = command(compose, 'test', '-e', DIRECTORY)
        end
      elsif %i[file_dropper_delete_file file_dropper_delete_dir].include?(event.method_id)
        row[:path] = event.binding.local_variable_get(event.method_id == :file_dropper_delete_file ? :file : :dir)
        row[:result] = event.return_value if event.event == :return
      end
      events << row
      File.open(File.join(directory, 'lucee-lifecycle-events.jsonl'), 'a') { |file| file.puts(JSON.generate(row)) }
    end
    framework.instance_variable_set(:@lucee_lifecycle_events, events)
    framework.instance_variable_set(:@lucee_lifecycle_trace, trace)
    trace.enable
    { installed: true }
  end
end
