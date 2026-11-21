# frozen_string_literal: true

require 'csv'
require_relative '../redis_lua/acceptance'

# The same real service gates original command, login, loot, upload and check paths.
module RedisProtocolTarget
  include RedisLuaTarget

  SERVER = 'auxiliary/scanner/redis/redis_server'
  LOGIN = 'auxiliary/scanner/redis/redis_login'
  EXTRACTOR = 'auxiliary/gather/redis_extractor'
  UPLOAD = 'auxiliary/scanner/redis/file_upload'

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'redis-protocol-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rl_native(action, *arguments)
    arguments = [CALLBACK_PORT.to_s] if %w[before state].include?(action)
    argv = ['python3', '-B', 'test/module_targets/redis_protocol_utf8/native_probe.py', action, *arguments]
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { action: action, argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), output + error
    JSON.parse(output)
  end

  def rp_ready
    rl_ready
    @rc[:protocol_observer] = rc_json("begin;require 'metasploit/framework/login_scanner/redis';load 'test/module_targets/redis_protocol_utf8/observe.rb';RedisProtocolObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    @rc[:statuses] = rc_json('{success:Metasploit::Model::Login::Status::SUCCESSFUL,incorrect:Metasploit::Model::Login::Status::INCORRECT}')
    @rc[:protocol_prepared] = true
    rc_save
  end

  def rp_call(owner, label, options = {}, action: 'run', reuse: false, typed: true, password: nil)
    console_command('back') unless reuse
    expect(console_command('use ' + owner)).not_to match(/Failed to load|Unknown command|No results/) unless reuse
    password ||= @rc.fetch(:settings).fetch('password')
    offset = rc_json('framework.instance_variable_get(:@redis_protocol_events).length')
    call = { owner: owner, label: label, options: options, typed: typed }
    @rc[:calls] << call
    settings = { 'READ_TIMEOUT' => 1 }.merge(options)
    if typed
      # RPC/IRB callers can supply real UTF-8 strings. Console byte input alone
      # would conceal character-count bugs when its lexer returns binary strings.
      rc_json("begin;active_module.datastore['PASSWORD']=#{password.inspect}.force_encoding('UTF-8');true;end")
    else
      settings['PASSWORD'] = password
    end
    %w[LocalFile RemoteFile].each do |name|
      next unless settings.key?(name)

      rc_json("begin;active_module.datastore[#{name.inspect}]=#{settings.delete(name).inspect}.force_encoding('UTF-8');true;end")
    end
    run_target_module(owner, 'target', settings, action: action, reuse_module: true, allow_errors: true, command_timeout: 60) do |output|
      call[:output] = output
      call[:events] = rc_json("framework.instance_variable_get(:@redis_protocol_events).drop(#{offset})")
      call[:selection] = rc_json('{object:active_module.object_id,password_encoding:active_module.datastore["PASSWORD"].encoding.name}')
      rc_save
    end
    call
  end

  def rp_server
    %w[INFO PING].each do |command|
      [false, true].each do |typed|
        call = rp_call(SERVER, command + '-' + typed.to_s, { 'COMMAND' => command }, typed: typed)
        expect(call.fetch(:output)).to include('Found redis with ' + command + ' command')
        expect(call.fetch(:events).select { |event| event['service'] }).not_to be_empty
        expect(call.fetch(:selection).fetch('password_encoding')).to eq('UTF-8') if typed
      end
    end
    rl_idle
  end

  def rp_login
    calls = [[:success, nil], [:incorrect, 'wrong-password'], [:success, nil]].map.with_index do |(expected, password), index|
      call = rp_call(LOGIN, 'login-' + index.to_s, { 'PASS_FILE' => '', 'BLANK_PASSWORDS' => false, 'STOP_ON_SUCCESS' => true }, reuse: index.positive?, password: password)
      results = call.fetch(:events).filter_map { |event| event['login'] }
      expect(results).not_to be_empty
      expect(results.map { |result| result.fetch('status') }.uniq).to eq([@rc.fetch(:statuses).fetch(expected.to_s)])
      expect(results.map { |result| result.fetch('password_encoding') }.uniq).to eq(['UTF-8'])
      call
    end
    expect(calls.map { |call| call.fetch(:selection).fetch('object') }.uniq.length).to eq(1)
    rl_idle
  end

  def rp_extract
    selections = 2.times.map do |index|
      call = rp_call(EXTRACTOR, 'extract-' + index.to_s, {}, reuse: index.positive?)
      values = call.fetch(:events).select { |event| event['event'] == 'return' && event['method'] == 'value_for_key' }.to_h { |event| [event.fetch('key_base64'), event.fetch('value')] }
      @rc.fetch(:readiness).fetch('values').each { |key, value| expect(values.fetch(key)).to eq(value) }
      paths = call.fetch(:output).scan(/Redis data stored at (.+)$/).flatten.map(&:strip)
      expect(paths.length).to eq(2)
      call[:loot] = paths.map do |path|
        expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
        raw = File.binread(path)
        # Array#to_csv writes LF rows; embedded CRLF must not select the separator.
        { path: path, base64: Base64.strict_encode64(raw), rows: CSV.parse(raw, row_sep: "\n") }
      end
      rows = call.fetch(:loot).flat_map { |loot| loot.fetch(:rows) }.to_h
      @rc.fetch(:readiness).fetch('values').each do |key, value|
        next unless value.fetch('kind') == 'string'

        expect(rows.fetch(Base64.strict_decode64(key))).to eq(Base64.strict_decode64(value.fetch('base64')))
      end
      rc_save
      rl_idle
      call.fetch(:selection).fetch('object')
    end
    expect(selections.uniq.length).to eq(1)
  end

  def rp_upload
    local = File.join(target_runtime.fetch('artifacts'), 'upload.txt')
    File.binwrite(local, "upload '雪'\0payload\r\n")
    selections = 2.times.map do |index|
      path = "/tmp/module-target-redis-upload-#{index}-☃.rdb"
      expect(rl_native('file', path)).to eq('exists' => false)
      call = rp_call(UPLOAD, 'upload-' + index.to_s, { 'LocalFile' => local, 'RemoteFile' => path }, reuse: index.positive?)
      call[:proof] = rl_native('file', path)
      rc_save
      expect(call.fetch(:proof)).to include('exists' => true, 'uid' => 101)
      bytes = Base64.strict_decode64(call.fetch(:proof).fetch('base64'))
      expect(bytes).to start_with('REDIS')
      expect(bytes).to include(Base64.strict_decode64(@rc.fetch(:readiness).fetch('upload_control').fetch('payload_base64')))
      expect(call.fetch(:output).b).to include(('bytes inside of redis DB at ' + path).b)
      rl_idle
      call.fetch(:selection).fetch('object')
    ensure
      rl_native('file', path, 'remove') if path
      rl_native('remove-default-rdb')
    end
    expect(selections.uniq.length).to eq(1)
  end

  def rp_check
    calls = 2.times.map do |index|
      call = rp_call(OWNER, 'lua-check-' + index.to_s, {}, action: 'check', reuse: index.positive?)
      codes = call.fetch(:events).filter_map { |event| event['check'] }
      expect(codes).to eq([{ 'code' => 'vulnerable', 'reason' => "Successfully executed the 'id' command." }])
      call
    end
    expect(calls.map { |call| call.fetch(:selection).fetch('object') }.uniq.length).to eq(1)
    rl_idle
  end
end
