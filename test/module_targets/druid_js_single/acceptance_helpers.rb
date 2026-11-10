# frozen_string_literal: true

# Reuses the sealed assertion contracts in a separate single-release context.
module DruidSingleAcceptance
  def artifact(name)
    File.join(target_runtime.fetch('artifacts'), name)
  end

  def owner
    'exploit/linux/http/apache_druid_js_rce'
  end

  def native_command_proof(command, path, bytes)
    expect(target_exec('app', '/bin/sh', '-c', command)).to eq('')
    expect(target_exec('app', 'cat', path)).to eq(bytes)
    expect(target_exec('app', 'stat', '-c', '%u:%g', path).strip).to eq('1000:1000')
    target_exec('app', 'rm', '--', path)
    expect(target_exec('app', 'test', '!', '-e', path)).to eq('')
    File.open(artifact('intended-commands.jsonl'), 'a') { |log| log.puts(JSON.generate(command_base64: Base64.strict_encode64(command), proof_base64: Base64.strict_encode64(bytes), native_producer: '/bin/sh -c', exact_bytes: true, marker_absent_before_framework: true)) }
  end

  def prove_executing_input(command)
    rows = File.readlines(artifact('executing-inputs.jsonl')).map { |line| JSON.parse(line) }
    encoded = Base64.strict_encode64(command)
    matching = rows.select { |row| row['kind'] == 'exploit' && row['fullname'] == owner && row['command_base64'] == encoded }
    expect(matching).not_to be_empty
    expect(matching.last.fetch('target_index')).to eq(@command_target)
    expect(matching.last.fetch('payload')).to eq('cmd/unix/generic')
    expect(rows).to include(hash_including('kind' => 'execute_command', 'fullname' => owner, 'argument_base64' => encoded))
    @intended_commands << command
  end

  def invoke(service, options, action: 'run -z', allow_errors: false)
    defaults = { 'TARGETURI' => '/', 'SSL' => false, 'HttpClientTimeout' => 8, 'HttpTrace' => true, 'HttpTraceHeadersOnly' => true }
    output = run_target_module(owner, service, defaults.merge(options), action: action, allow_errors: allow_errors, command_timeout: 55)
    expect(output).not_to include('Unknown datastore option', 'Invalid option', 'Parse error:', 'not a compatible payload')
    output
  end

  def generic_options(command)
    { 'TARGET' => @command_target, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => command, 'WfsDelay' => 2, 'DisablePayloadHandler' => false }
  end

  def target_files
    target_exec('app', 'find', '/tmp', '-mindepth', '1', '-maxdepth', '1', '-print').lines.map(&:strip).sort
  end

  def capture_created_files
    (target_files - @before_files).each do |path|
      type = target_exec('app', 'stat', '-c', '%F', path).strip
      name = "target-#{@case_id}-#{File.basename(path)}"
      if type == 'regular file'
        output, status = Open3.capture2e(*target_runtime.fetch('compose'), 'cp', "app:#{path}", artifact(name))
        File.open(artifact('native-copies.jsonl'), 'a') { |log| log.puts(JSON.generate(source: path, destination: name, exitstatus: status.exitstatus, output: output)) }
        expect(status.success?).to be(true), output
      else
        File.open(artifact('native-other-artifacts.jsonl'), 'a') { |log| log.puts(JSON.generate(path: path, type: type)) }
      end
    end
  end

  def restore_files
    created = target_files - @before_files
    created.each { |path| target_exec('app', 'rm', '-rf', '--', path) }
    expect(target_files).to eq(@before_files)
    File.open(artifact('restorations.jsonl'), 'a') { |log| log.puts(JSON.generate(case: @case_id, removed: created, exact_inventory_restored: true)) }
  end

  def prove_ports_removed
    script = "require 'socket'; require 'json'; print JSON.generate([3389,4445,8081].to_h{|port| begin; socket=TCPSocket.new('#{listener_host}',port); socket.close; [port,'LISTENING']; rescue Errno::ECONNREFUSED; [port,'CLOSED']; end})"
    argv = target_runtime.fetch('compose') + ['exec', '-T', 'framework', 'ruby', '-e', script]
    output, status = Open3.capture2e(*argv)
    File.open(artifact('listener-audit.jsonl'), 'a') { |log| log.puts(JSON.generate(argv: argv, exitstatus: status.exitstatus, output: output)) }
    expect(status.success?).to be(true), output
    expect(JSON.parse(output)).to eq('3389' => 'CLOSED', '4445' => 'CLOSED', '8081' => 'CLOSED')
  end

  def socket_state
    output = console_command("irb -e 'puts \"DRUID_OBSERVER_STATE=\" + DruidSingleSocketObserver.state.to_json'")
    state = JSON.parse(output[/DRUID_OBSERVER_STATE=(\{.*\})/, 1])
    expect(state.fetch('errors')).to eq([])
    state
  end

  def verify_socket_rows(case_id)
    rows = File.readlines(artifact('socket-observations.jsonl')).map { |line| JSON.parse(line) }.select { |row| row.fetch('case_id') == case_id }
    requests = rows.select { |row| row.fetch('kind') == 'PRE-SEND' }
    expect(requests).not_to be_empty
    functions = []
    requests.each do |before|
      key = before.values_at('client', 'attempt')
      writes = rows.select { |row| row.fetch('kind') == 'SOCKET-WRITE' && row.values_at('client', 'attempt') == key }
      replies = rows.select { |row| row.fetch('kind') == 'RESPONSE' && row.values_at('client', 'attempt') == key }
      expect(writes.length).to eq(1)
      expect(replies.length).to eq(1)
      write = writes.fetch(0)
      expect(write.fetch('complete')).to be(true)
      expect(write['error']).to be_nil
      expect(write.fetch('returned_count')).to eq(write.fetch('bytes'))
      expect(write.fetch('ssl')).to be(false)
      expect([nil, '']).to include(write['proxies'])
      expect(before.fetch('transformed')).to be(false)
      expect(write.fetch('peer')[1..2]).to eq(write.values_at('host', 'port'))
      expect(replies.fetch(0).fetch('status')).to be_a(Integer)
      request = Rex::Proto::Http::Request.new
      bytes = Base64.strict_decode64(write.fetch('data_base64'))
      expect(request.parse(bytes)).to eq(Rex::Proto::Http::Packet::ParseCode::Completed)
      expect(request.bufq).to eq('')
      expect(request.headers['Content-Length'].to_i).to eq(request.body.bytesize)
      expect(request.body.b).to eq(Base64.strict_decode64(before.fetch('body_base64')))
      next if request.body.empty?

      document = JSON.parse(request.body)
      functions << document.dig('spec', 'dataSchema', 'parser', 'parseSpec', 'function')
    end
    @intended_commands.each do |command|
      matched = functions.compact.any? { |function| function.include?(command) || function.include?(command.to_json) }
      File.open(artifact('socket-command-audit.jsonl'), 'a') { |log| log.puts(JSON.generate(command_base64: Base64.strict_encode64(command), actual_socket_write_argument_matched: matched)) }
      expect(matched).to be(true), 'Intended command missing from actual SOCKET-WRITE data'
    end
    socket_state
    rows
  end
end
