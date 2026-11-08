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

  it 'uploads a file twice, preserves data and restores Redis configuration' do
    service = 'open'
    expect(target_exec(service, 'redis-cli', 'FLUSHALL').strip).to eq('OK')
    expect(target_exec(service, 'redis-cli', 'SET', 'preserve-me', 'original-value').strip).to eq('OK')
    original = target_exec(service, 'redis-cli', 'CONFIG', 'GET', 'dir', 'dbfilename', 'rdbcompression')
    local_file = File.join(target_runtime.fetch('artifacts'), 'upload.txt')
    File.write(local_file, "module-target-upload-marker\n")
    2.times do
      output = run_target_module('auxiliary/scanner/redis/file_upload', service, {
        'PASSWORD' => '', 'LocalFile' => local_file, 'RemoteFile' => '/tmp/module-target-upload.rdb'
      })
      expect(output).to include('bytes inside of redis DB at /tmp/module-target-upload.rdb')
      expect(target_exec(service, 'cat', '/tmp/module-target-upload.rdb')).to include('module-target-upload-marker')
      expect(target_exec(service, 'redis-cli', 'GET', 'preserve-me').strip).to eq('original-value')
      expect(target_exec(service, 'redis-cli', 'CONFIG', 'GET', 'dir', 'dbfilename', 'rdbcompression')).to eq(original)
      expect(target_exec(service, 'redis-cli', 'DBSIZE').strip).to eq('1')
    end
  end

  it 'does not report file upload as vulnerable when protected configuration prevents it' do
    # Redis 7 refuses CONFIG SET dir by default. CONFIG GET alone cannot prove a write.
    expect(target_exec('modern', 'redis-cli', 'CONFIG', 'SET', 'dir', '/tmp')).to include("can't set protected config")
    output = run_target_module('auxiliary/scanner/redis/file_upload', 'modern', { 'PASSWORD' => '' }, action: 'check')
    expect(output).not_to include('The target is vulnerable.')
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
