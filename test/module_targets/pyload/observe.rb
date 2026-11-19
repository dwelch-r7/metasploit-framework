# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'

# Observe actual module methods and their HTTP exchanges without changing them.
module PyloadObservation
  OWNERS = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).fetch('owners').freeze
  METHODS = %i[check exploit execute_command execute_python execute_javascript execute_cmdstager].freeze

  def self.install(framework)
    events = []
    responses = File.join(File.dirname(Msf::Config.config_directory), 'owner-http')
    FileUtils.mkdir_p(responses)
    event_path = File.join(File.dirname(Msf::Config.config_directory), 'owner-events.jsonl')
    File.write(event_path, '')
    append = lambda do |row|
      events << row
      File.open(event_path, 'a') { |output| output.puts(JSON.generate(row)) }
    end
    sources = OWNERS.values.to_h do |fullname|
      source = File.expand_path('modules/' + fullname.sub('exploit/', 'exploits/') + '.rb')
      owner = framework.modules.create(fullname)
      observer = Module.new do
        define_method(:send_request_cgi) do |*arguments, **keywords|
          request = arguments.first || keywords
          response = super(*arguments, **keywords)
          body_path = File.join(responses, events.length.to_s + '.body') if response
          File.binwrite(body_path, response.body.b) if response
          append.call(event: 'http', owner: fullname, object: object_id, request: request,
                      code: response&.code, body_sha256: response && Digest::SHA256.hexdigest(response.body.b), body_path: body_path)
          response
        end
      end
      owner.class.prepend(observer)
      [source, { owner: fullname, sha256: Digest::SHA256.file(source).hexdigest }]
    end
    trace = TracePoint.new(:call, :return) do |event|
      next unless METHODS.include?(event.method_id) && sources.key?(File.expand_path(event.path))

      row = {
        event: event.event, owner: sources.fetch(File.expand_path(event.path)).fetch(:owner),
        method: event.method_id, object: event.self.object_id, auto_check: event.self.datastore['AutoCheck']
      }
      if event.event == :return && event.return_value.is_a?(Msf::Exploit::CheckCode)
        result = event.return_value
        row[:result] = { code: result.code, reason: result.reason, message: result.message }
      end
      if event.event == :return && event.method_id == :exploit && event.self.exe
        row[:delivery] = {
          flavor: event.self.flavor, commands: event.self.cmd_list,
          exe_sha256: Digest::SHA256.hexdigest(event.self.exe),
          elf_header_hex: event.self.exe.b.bytes.first(64).map { |byte| '%02x' % byte }.join
        }
      end
      append.call(row)
    end
    framework.instance_variable_set(:@pyload_events, events)
    framework.instance_variable_set(:@pyload_trace, trace)
    trace.enable
    { installed: true, sources: sources, config: Msf::Config.config_directory, events: event_path }
  end
end
