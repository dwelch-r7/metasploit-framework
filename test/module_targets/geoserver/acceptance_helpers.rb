# frozen_string_literal: true

# Exact target/loot proof shared by the three bounded release profiles.
module GeoServerAcceptance
  RCE = 'exploit/multi/http/geoserver_unauth_rce_cve_2024_36401'
  XXE = 'auxiliary/gather/geoserver_wms_getmap_xxe_file_read'

  def artifact(name)
    File.join(target_runtime.fetch('artifacts'), name)
  end

  def returned_inputs
    File.readlines(artifact('geoserver-returned-inputs.jsonl')).map { |line| JSON.parse(line) }
  end

  def invoke(owner, service, options = {}, action: 'run', allow_errors: false)
    offset = returned_inputs.length
    defaults = { 'TARGETURI' => owner == RCE ? '/' : '/geoserver', 'SSL' => false, 'HttpClientTimeout' => 8, 'HttpTrace' => true, 'HttpTraceHeadersOnly' => true }
    # Body bytes are retained in REQUEST-ARGS/RESPONSE-BODY records. Printing
    # ClassCastException in HttpTrace would collide with the console guard.
    output = run_target_module(owner, service, defaults.merge(options), action: action, allow_errors: allow_errors, command_timeout: 55)
    expect(output).not_to match(/Unknown datastore option|Invalid option|Parse error:|not a compatible payload/)
    @last_inputs = returned_inputs.drop(offset)
    expect(@last_inputs).to include(hash_including('kind' => 'REQUEST-ARGS/RESPONSE-BODY', 'owner' => owner))
    output
  end

  def generic_options(command)
    { 'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => command, 'DisablePayloadHandler' => true, 'WfsDelay' => 0 }
  end

  def target_files
    target_exec('app', 'find', '/tmp', '-maxdepth', '1', '-name', 'module-target-geoserver-*', '-print').lines.map(&:strip).sort
  end

  def loot_files
    Dir[File.join(target_runtime.fetch('artifacts'), 'msf-config', 'loot', '*')].select { |path| File.file?(path) }.sort
  end

  def absent(path)
    expect(target_exec('app', 'test', '!', '-e', path)).to eq('')
  end

  def restore_files
    created = target_files - @before_files
    created.each { |path| target_exec('app', 'rm', '-f', '--', path) }
    expect(target_files).to eq(@before_files)
    File.open(artifact('restorations.jsonl'), 'a') { |file| file.puts(JSON.generate(case: @case_id, removed: created, exact_owned_inventory_restored: true)) }
  end

  def prove_producer(owner, argument)
    producer = @last_inputs.select { |row| row['kind'] == 'RETURNED-XML' && row['owner'] == owner && row['arguments'].first == argument }
    expect(producer.length).to eq(1)
    actual = producer.fetch(0).fetch('returned_base64')
    requests = @last_inputs.select { |row| row['kind'] == 'REQUEST-ARGS/RESPONSE-BODY' && row['owner'] == owner && row['data_base64'] == actual }
    expect(requests.length).to eq(1)
    expect(requests.fetch(0).fetch('status')).to be_a(Integer)
    if owner == XXE
      uri = @last_inputs.find { |row| row['kind'] == 'RETURNED-URI' && row['owner'] == owner }
      expect(requests.fetch(0).fetch('uri')).to eq(Base64.strict_decode64(uri.fetch('returned_base64')))
    else
      expect(Base64.strict_decode64(actual)).to include(Base64.strict_encode64(argument))
    end
  end

  def prove_command(service, options, iteration, bytes:)
    marker = "/tmp/module-target-geoserver-command-#{@case_id}-#{iteration}"
    count = "#{marker}-count"
    command = bytes.empty? ? ":>#{marker};printf${IFS}x>>#{count}" : "printf${IFS}%s${IFS}#{bytes}>#{marker};printf${IFS}x>>#{count}"
    expect(Rex::Parser::Arguments.from_s(format_datastore_options('CMD' => command))).to eq(["CMD=#{command}"])
    [marker, count].each { |path| absent(path) }
    expect(target_exec('app', '/bin/sh', '-c', command)).to eq('')
    expect(target_exec('app', 'cat', marker)).to eq(bytes)
    expect(target_exec('app', 'cat', count)).to eq('x')
    restore_files
    output = invoke(RCE, service, generic_options(command).merge(options))
    prove_producer(RCE, command)
    Timeout.timeout(15) do
      wait_for_expect(20, 0.1) do
        expect(target_exec('app', 'sh', '-c', 'if test -f "$1"; then printf present; fi', 'sh', marker)).to eq('present')
      end
    end
    expect(target_exec('app', 'cat', marker)).to eq(bytes)
    evaluations = target_exec('app', 'cat', count)
    expect(evaluations).to match(/\Ax+\z/)
    File.open(artifact('command-proofs.jsonl'), 'a') do |file|
      file.puts(JSON.generate(command_base64: Base64.strict_encode64(command), target_bytes_base64: Base64.strict_encode64(bytes), observed_append_evaluations: evaluations.length, output: output))
    end
    expect(loot_files).to eq(@before_loot)
    restore_files
  end

  def read_file_twice(service = 'app', options = {}, positive: true, path: @native.fetch('text_path'))
    2.times do
      previous = loot_files
      output = invoke(XXE, service, { 'FILEPATH' => path }.merge(options), allow_errors: !positive)
      prove_producer(XXE, path)
      if positive
        expect(output).to include('Successfully read file:')
        fresh = loot_files - previous
        expect(fresh.length).to eq(1)
        expect(File.binread(fresh.fetch(0))).to eq(Base64.strict_decode64(@native.fetch('text_base64')))
      else
        expect(output).not_to include('Successfully read file:', 'File saved to:')
        expect(loot_files).to eq(previous)
      end
      expect(target_files).to eq(@before_files)
    end
  end

  def console_command(command, timeout: 40)
    raise Acceptance::ChildProcessTimeoutError, 'GeoServer console transport already failed' if @console_broken

    super
  rescue Acceptance::ChildProcessRecvError, Acceptance::ChildProcessTimeoutError, EOFError, Errno::EPIPE
    @console_broken = true
    RSpec.world.wants_to_quit = true
    raise
  end
end
