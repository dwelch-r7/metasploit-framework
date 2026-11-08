require 'acceptance_spec_helper'

RSpec.describe 'Redis module targets' do
  include_context 'module target'

  %w[open authenticated modern].each do |service|
    context service do
      let(:password) { service == 'authenticated' ? 'module-test-password' : '' }
      let(:redis_cli) { password.empty? ? ['redis-cli'] : ['redis-cli', '--no-auth-warning', '-a', password] }

      before do
        # Validate the actual service and authentication independently of Framework.
        version = service == 'modern' ? '7.2.4' : '6.2.14'
        expect(target_exec(service, *redis_cli, 'INFO', 'server')).to include("redis_version:#{version}")
        expect(target_exec(service, *redis_cli, 'PING').strip).to eq('PONG')
        expect(target_exec(service, *redis_cli, 'FLUSHALL').strip).to eq('OK')
      end

      it 'discovers the running server and reports its version' do
        output = run_target_module('auxiliary/scanner/redis/redis_server', service, { 'PASSWORD' => password })
        expect(output).to include('Found redis with INFO command', 'redis_version', service == 'modern' ? '7.2.4' : '6.2.14')
      end

      it 'executes a specified Redis command' do
        output = run_target_module('auxiliary/scanner/redis/redis_server', service, { 'PASSWORD' => password, 'COMMAND' => 'PING' })
        expect(output).to include('Found redis with PING command', '+PONG')
      end

      it 'recognizes the authentication configuration' do
        if service == 'authenticated'
          expect(target_exec(service, 'redis-cli', 'PING')).to include('NOAUTH')
        end
        output = run_target_module('auxiliary/scanner/redis/redis_login', service, {
          'PASSWORD' => password, 'PASS_FILE' => '', 'BLANK_PASSWORDS' => false, 'STOP_ON_SUCCESS' => true
        })
        expect(output).to include(service == 'authenticated' ? 'Login Successful' : 'No password is required.')
      end

      it 'extracts seeded strings, lists, sets, sorted sets, hashes and a second database' do
        seed_redis(service, redis_cli)
        output = run_target_module('auxiliary/gather/redis_extractor', service, { 'PASSWORD' => password })
        expect(output).to include('Connected to Redis version', 'Redis data stored at')
        %w[string-value list-value set-value sorted-value hash-value second-database-value].each do |value|
          expect(output).to include(value)
        end
        # Verify persisted output as well as console printing.
        loot_paths = output.scan(/Redis data stored at (.+)$/).flatten.map(&:strip)
        expect(loot_paths.length).to eq(2)
        loot = loot_paths.map do |path|
          expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
          File.read(path)
        end.join
        expect(loot).to include('string-value', 'second-database-value')
      end

      it 'handles an empty keyspace without claiming extraction' do
        output = run_target_module('auxiliary/gather/redis_extractor', service, { 'PASSWORD' => password })
        expect(output).to include('Connected to Redis version')
        expect(output).not_to include('Redis data stored at', 'Extracting about')
      end
    end
  end

  it 'rejects an incorrect password without reporting a successful login' do
    expect(target_exec('authenticated', 'redis-cli', '-a', 'wrong-password', 'PING', expected_exit: 1)).to include('WRONGPASS')
    output = run_target_module('auxiliary/scanner/redis/redis_login', 'authenticated', {
      'PASSWORD' => 'wrong-password', 'PASS_FILE' => '', 'BLANK_PASSWORDS' => false
    }, allow_errors: true)
    expect(output).to include('LOGIN FAILED')
    expect(output).not_to include('Login Successful', 'No password is required.')
  end

  %w[open authenticated].each do |service|
    it "uploads twice on #{service}, preserving real data and configuration" do
      password = service == 'authenticated' ? 'module-test-password' : ''
      cli, original, local_file = prepare_upload(service, password)
      2.times do
        expect_file_upload(service, password, cli, original, local_file)
      end
    end
  end

  {
    '/proc/module-target-failure.rdb' => /Failed to save/i,
    '/tmp/..' => /Failed to save/i,
    '/module-target-missing/failure.rdb' => /Failed to set the Redis snapshot directory/i
  }.each do |destination, error|
    it "restores state after #{destination} fails and permits another two uploads" do
      cli, original, local_file = prepare_upload('open', '')
      begin
        # Establish the intended server-side failure with the native client.
        begin
          if destination.start_with?('/proc/')
            expect(target_exec('open', *cli, 'CONFIG', 'SET', 'dir', '/proc').strip).to eq('OK')
            expect(target_exec('open', *cli, 'SAVE')).to include('ERR')
          elsif destination == '/tmp/..'
            expect(target_exec('open', *cli, 'CONFIG', 'SET', 'dir', '/tmp').strip).to eq('OK')
            expect(target_exec('open', *cli, 'CONFIG', 'SET', 'dbfilename', '..').strip).to eq('OK')
            expect(target_exec('open', *cli, 'SAVE')).to include('ERR')
          else
            expect(target_exec('open', *cli, 'CONFIG', 'SET', 'dir', File.dirname(destination))).to include('ERR')
          end
        ensure
          restore_fixture_configuration('open', cli, original.fetch(:config))
        end
        expect(redis_upload_state('open', cli)).to eq(original)
        output = run_target_module('auxiliary/scanner/redis/file_upload', 'open', {
          'PASSWORD' => '', 'LocalFile' => local_file, 'RemoteFile' => destination
        }, allow_errors: true)
        expect(redis_upload_state('open', cli)).to eq(original)
        expect(output).to match(error)
        2.times { expect_file_upload('open', '', cli, original, local_file) }
      ensure
        # A regression must fail this example without contaminating later cases.
        restore_fixture_configuration('open', cli, original.fetch(:config))
        expect(target_exec('open', *cli, 'FLUSHALL').strip).to eq('OK')
      end
    end
  end

  it 'does not report file upload as vulnerable when protected configuration prevents it' do
    # Redis 7 refuses CONFIG SET dir by default. CONFIG GET alone cannot prove a write.
    expect(target_exec('modern', 'redis-cli', 'CONFIG', 'SET', 'dir', '/tmp')).to include("can't set protected config")
    output = run_target_module('auxiliary/scanner/redis/file_upload', 'modern', { 'PASSWORD' => '' }, action: 'check')
    expect(output).to include('The target is not exploitable.', 'Redis protected configuration prevents changing dir and dbfilename')
    expect(output).not_to include('The target is vulnerable.')
  end

  def redis_upload_state(service, cli)
    # Redis 6.2 rejects multiple CONFIG GET patterns, with a zero CLI exit status.
    # Validate each response's shape so an error cannot masquerade as state.
    config = %w[dir dbfilename rdbcompression].to_h do |name|
      fields = target_exec(service, *cli, '--raw', 'CONFIG', 'GET', name).lines.map(&:chomp)
      expect(fields.length).to eq(2)
      expect(fields.first).to eq(name)
      [name, fields.last]
    end
    {
      config: config,
      keys: target_exec(service, *cli, '--raw', 'KEYS', '*').lines.map(&:chomp).reject(&:empty?).sort,
      sentinel: target_exec(service, *cli, '--raw', 'GET', 'preserve-me').strip
    }
  end

  def prepare_upload(service, password)
    cli = password.empty? ? ['redis-cli'] : ['redis-cli', '--no-auth-warning', '-a', password]
    expect(target_exec(service, *cli, 'PING').strip).to eq('PONG')
    expect(target_exec(service, *cli, 'FLUSHALL').strip).to eq('OK')
    expect(target_exec(service, *cli, 'SET', 'preserve-me', 'original-value').strip).to eq('OK')
    original = redis_upload_state(service, cli)
    expect(original.fetch(:keys)).to eq(['preserve-me'])
    expect(original.fetch(:sentinel)).to eq('original-value')
    local_file = File.join(target_runtime.fetch('artifacts'), "upload-#{service}.txt")
    File.write(local_file, "module-target-upload-marker\n")
    [cli, original, local_file]
  end

  def expect_file_upload(service, password, cli, original, local_file)
    destination = '/tmp/module-target-upload.rdb'
    target_exec(service, 'rm', '-f', destination)
    target_exec(service, 'test', '!', '-e', destination)
    output = run_target_module('auxiliary/scanner/redis/file_upload', service, {
      'PASSWORD' => password, 'LocalFile' => local_file, 'RemoteFile' => destination
    })
    expect(output).to include("bytes inside of redis DB at #{destination}")
    expect(target_exec(service, 'cat', destination)).to include('module-target-upload-marker')
    expect(redis_upload_state(service, cli)).to eq(original)
  end

  def restore_fixture_configuration(service, cli, config)
    config.each do |name, value|
      expect(target_exec(service, *cli, 'CONFIG', 'SET', name, value).strip).to eq('OK')
    end
  end

  def seed_redis(service, cli)
    {
      ['SET', 'string-key', 'string-value'] => 'OK',
      ['RPUSH', 'list-key', 'list-value'] => '1',
      ['SADD', 'set-key', 'set-value'] => '1',
      ['ZADD', 'sorted-key', '1', 'sorted-value'] => '1',
      ['HSET', 'hash-key', 'field', 'hash-value'] => '1'
    }.each do |command, result|
      expect(target_exec(service, *cli, *command).strip).to eq(result)
    end
    expect(target_exec(service, *cli, '-n', '2', 'SET', 'second-database-key', 'second-database-value').strip).to eq('OK')
  end
end
