# frozen_string_literal: true

require 'base64'
require 'digest'
require 'yaml'
require_relative '../saltstack_rce/acceptance'

module Acceptance
  # Use a genuine native session to inspect the ordinary post-module outputs.
  module SaltstackGather
    include SaltstackRce

    GATHER_OWNER = 'post/multi/gather/saltstack_salt'

    def sg_native(phase)
      output = +''
      argv = ['python3', 'test/module_targets/saltstack_gather/native_probe.py', ENV.fetch('MODULE_TARGET_RUNTIME'), phase]
      expect(ModuleTargetTests.new.send(:command, argv, path: File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log"), timeout: 300, capture: output, quiet: true)).to be(true), output
      JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-#{phase}.json")))
    end

    def sg_session(payload)
      expect(sx_json('framework.sessions.keys')).to eq([])
      File.write(File.join(target_runtime.fetch('artifacts'), 'ready-sessions.jsonl'), '')
      console_command('back')
      console_command('use exploit/multi/handler')
      { 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => SaltstackRce::CALLBACK, 'ExitOnSession' => false }.each do |name, value|
        console_command("set #{name} #{value}")
      end
      console_command('run -j -z')
      jobs = sx_json('framework.jobs.keys')
      expect(jobs.length).to eq(1)
      generated = sx_json("RocketmqSessionControl.command(framework.jobs.fetch(#{jobs.first.inspect}),#{payload.inspect})")
      output = target_exec('target', 'python', '-c', File.read('test/module_targets/saltstack_gather/sdk_launch.py'), generated.fetch('command_base64'), payload.start_with?('python/') ? 'python' : 'command')
      launch = sx_document(output, 'SALT_GATHER_SDK=')
      sx_record('native-payload-dispatches.jsonl', workspace: @workspace, generated: generated, launch: launch)
      expect(launch.fetch('payload_sha256')).to eq(generated.fetch('sha256'))
      expect(launch.fetch('status')).to eq('sdk_dispatched')
      sx_ready(1).fetch(0)
    end

    def sg_snapshot(label)
      rows = sx_json('framework.db.loots(workspace: framework.db.workspace).map { |loot| {id: loot.id, type: loot.ltype, path: loot.path, host: loot.host&.address, info: loot.info} }')
      rows.each do |row|
        bytes = File.binread(row.fetch('path'))
        row['bytes_base64'] = Base64.strict_encode64(bytes)
        row['sha256'] = Digest::SHA256.hexdigest(bytes)
      end
      data = { workspace: @workspace, label: label, loot: rows }
      %w[hosts services notes].each do |table|
        query = if table == 'hosts'
                  "SELECT coalesce(json_agg(row_to_json(t)),'[]'::json) FROM hosts t JOIN workspaces w ON w.id=t.workspace_id WHERE w.name='#{@workspace}'"
                else
                  "SELECT coalesce(json_agg(row_to_json(t)),'[]'::json) FROM #{table} t JOIN hosts h ON h.id=t.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}'"
                end
        data[table] = JSON.parse(sx_sql(query))
      end
      data['credentials'] = sx_json('framework.db.creds(workspace: framework.db.workspace).map { |credential| {id: credential.id, public: credential.public&.data, private: credential.private&.data, private_type: credential.private&.type, logins: credential.logins.map { |login| {status: login.status, address: login.service.host.address, port: login.service.port, name: login.service.name} } } }')
      sx_record('collection-snapshots.jsonl', data)
      data
    end

    def sg_call(identifier, options, label)
      console_command('back')
      selected = console_command("use #{GATHER_OWNER}")
      expect(selected).not_to match(/Failed to load|Unknown command|No results/)
      values = { 'SESSION' => identifier, 'VERBOSE' => true, 'TIMEOUT' => 120 }.merge(options)
      output = console_command("run #{format_datastore_options(values)}", timeout: 240)
      sx_record('owning-calls.jsonl', workspace: @workspace, owner: GATHER_OWNER, label: label, options: values, output: output)
      snapshot = sg_snapshot(label)
      expect(output).not_to match(/Exception|undefined method|Unknown command|Msf::OptionValidateError|Post failed|\[-\]/)
      expect(output).to include('Post module execution completed')
      snapshot
    end
  end
end
