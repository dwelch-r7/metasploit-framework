# frozen_string_literal: true

require 'base64'
require 'digest'
require 'openssl'
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
      @gather_payload = payload
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
      identifier = sx_ready(1).fetch(0)
      @gather_session = identifier
      path = "/tmp/module-target-salt-proof-#{SecureRandom.hex(6)}"
      value = "salt-gather-#{SecureRandom.hex(12)}"
      proof = sx_json("SaltSessionControl.proof(framework,#{identifier},#{path.inspect},#{value.inspect})")
      expect(proof.fetch('role')).to eq('master')
      expect(proof.fetch('token')).to eq(@native.fetch('cluster').fetch('roles').fetch('master').fetch('token'))
      expect(proof.fetch('via_exploit')).to eq('exploit/multi/handler')
      expect(proof.fetch('type')).to eq(payload.include?('meterpreter') ? 'meterpreter' : 'shell')
      expect(target_exec('target', 'cat', path)).to eq(value)
      expect(target_exec('target', 'stat', '-c', '%u', path).strip).to eq('0')
      sessions = sx_sessions_sql
      expect(sessions.map { |row| row.fetch('id') }).to include(proof.fetch('db_id'))
      host_id = sessions.find { |row| row.fetch('id') == proof.fetch('db_id') }.fetch('host_id')
      expect(host_id).to be_a(Integer)
      @pre_collection_host = JSON.parse(sx_sql("SELECT row_to_json(h) FROM hosts h WHERE h.id=#{host_id}"))
      sx_record('pre-collection-hosts.jsonl', workspace: @workspace, host: @pre_collection_host)
      target_exec('target', 'rm', '-f', path)
      sx_record('pre-collection-session-proofs.jsonl', workspace: @workspace, proof: proof, proof_sha256: Digest::SHA256.hexdigest(value))
      identifier
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
      data['credentials'] = sx_json('framework.db.creds(workspace: framework.db.workspace).sort_by(&:id).map { |credential| {id: credential.id, public: credential.public&.username, private: credential.private&.data, private_type: credential.private&.type, logins: credential.logins.sort_by(&:id).map { |login| {id: login.id, status: login.status, address: login.service.host.address, port: login.service.port, name: login.service.name} } } }')
      data['decoded_notes'] = sx_json('framework.db.notes(workspace: framework.db.workspace).map { |note| {type: note.ntype, host: note.host&.address, data: note.data} }')
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
      snapshot.merge(output: output)
    end

    def sg_yaml(loot)
      YAML.safe_load(Base64.strict_decode64(loot.fetch('bytes_base64')))
    end

    def sg_verify(snapshot, options, previous_ids: [])
      entries = snapshot.fetch(:loot).reject { |row| previous_ids.include?(row.fetch('id')) }
      types = %w[saltstack_minion saltstack_minions saltstack_sls saltstack_roster ssh_key ssh_key saltstack_pillar_data_gather]
      data_enabled = %w[GETHOSTNAME GETIP GETOS].any? { |key| options.fetch(key, true) }
      types << 'saltstack_minion_data_gather' if data_enabled
      expect(entries.map { |row| row.fetch('type') }.sort).to eq(types.sort)
      by_type = entries.group_by { |row| row.fetch('type') }
      cluster = @native.fetch('cluster')
      expect(sg_yaml(by_type.fetch('saltstack_minion').fetch(0))).to eq(cluster.fetch('minion_config'))
      expect(sg_yaml(by_type.fetch('saltstack_minions').fetch(0))).to eq(cluster.fetch('keys'))
      expect(sg_yaml(by_type.fetch('saltstack_roster').fetch(0))).to eq(cluster.fetch('inputs').fetch('roster'))
      expected_nodes = options['MINIONS'] == 'module-target-minion-a' ? ['module-target-minion-a'] : cluster.fetch('keys').fetch('minions')
      sls = sg_sls_blocks(Base64.strict_decode64(by_type.fetch('saltstack_sls').fetch(0).fetch('bytes_base64')))
      native_sls = sg_sls_blocks(cluster.fetch('sls'))
      expect(sls.keys.sort).to eq(expected_nodes.sort)
      expected_nodes.each do |node|
        expect(sls.fetch(node)).to eq(native_sls.fetch(node))
        expect(sls.fetch(node)).to include('module-target-state-marker')
      end
      pillars = sg_yaml(by_type.fetch('saltstack_pillar_data_gather').fetch(0))
      expect(pillars.keys.sort).to eq(expected_nodes.sort)
      expect(pillars.values).to all(eq(cluster.fetch('inputs').fetch('pillar')))
      keys = by_type.fetch('ssh_key').map { |row| row.fetch('sha256') }
      expect(keys.sort).to eq(%w[plain encrypted].map { |name| cluster.fetch('inputs').fetch('files').fetch("/etc/salt/pki/collection/#{name}.pem") }.sort)
      sg_verify_table(snapshot.fetch(:output), cluster.fetch('keys'))
      sg_verify_credentials(snapshot, cluster)
      sg_verify_host(snapshot, options, cluster)
      return unless data_enabled

      results = sg_yaml(by_type.fetch('saltstack_minion_data_gather').fetch(0))
      expect(results.keys.sort).to eq(expected_nodes.sort)
      expected_nodes.each do |node|
        result = results.fetch(node)
        { 'GETHOSTNAME' => ['network.get_hostname', 'hostname'], 'GETIP' => ['network.interfaces', 'ip'], 'GETOS' => ['grains.item', nil] }.each do |option, (function, variant)|
          if options.fetch(option, true)
            expected = option == 'GETOS' ? cluster.fetch('os_grains').fetch(node) : cluster.fetch('collection_variants').fetch(variant).fetch(node)
            expect(result.fetch(function)).to eq(expected)
          else
            expect(result).not_to have_key(function)
          end
        end
      end
    end

    def sg_verify_host(snapshot, options, cluster)
      host = snapshot.fetch('hosts').find { |entry| entry.fetch('id') == @pre_collection_host.fetch('id') }
      expect(host).not_to be_nil
      if options.fetch('GETIP', true) && options.fetch('GETHOSTNAME', true)
        expect(host.fetch('name')).to eq(cluster.fetch('collection_variants').fetch('hostname').values.first)
      else
        expect(host.fetch('name')).to eq(@pre_collection_host.fetch('name'))
      end
      if options.fetch('GETIP', true) && options.fetch('GETOS', true)
        grains = cluster.fetch('os_grains').values.first
        expect(host.fetch('os_name')).to eq(grains.fetch('kernel'))
        expect(host.fetch('os_flavor')).to eq("#{grains.fetch('osfullname')} #{grains.fetch('osrelease')}")
      else
        expect(host.values_at('os_name', 'os_flavor')).to eq(@pre_collection_host.values_at('os_name', 'os_flavor'))
      end
    end

    def sg_sls_blocks(text)
      text.split(/(?=^module-target-minion-[ab]:$)/).reject(&:empty?).to_h do |block|
        name, body = block.split("\n", 2)
        [name.delete_suffix(':'), body.to_s.strip]
      end
    end

    def sg_verify_table(output, keys)
      { 'minions' => 'Accepted', 'minions_pre' => 'Unaccepted', 'minions_rejected' => 'Rejected', 'minions_denied' => 'Denied' }.each do |key, status|
        keys.fetch(key).each do |node|
          expect(output).to match(/^[ \t]+#{status}[ \t]+#{Regexp.escape(node)}[ \t]*$/)
        end
      end
    end

    def sg_verify_credentials(snapshot, cluster)
      credentials = snapshot.fetch('credentials')
      expect(credentials.map { |credential| credential.values_at('public', 'private_type', 'private') }.uniq.length).to eq(3)
      logins = credentials.flat_map { |credential| credential.fetch('logins') }
      roster = cluster.fetch('inputs').fetch('roster')
      expect(logins.map { |login| [login.fetch('address'), login.fetch('port'), login.fetch('status')] }.sort).to eq(roster.values.map { |entry| [entry.fetch('host'), entry.fetch('port', 22), 'Untried'] }.sort)
      expect(credentials.map { |credential| credential.fetch('public') }.uniq).to eq(['root'])
      expect(logins.map { |login| login.fetch('name').downcase }.uniq).to eq(['ssh'])
      password = credentials.find { |credential| credential.fetch('private_type') == 'Metasploit::Credential::Password' }
      expect(password.fetch('private')).to eq(roster.fetch('collection-password').fetch('passwd'))
      private_keys = credentials.reject { |credential| credential.equal?(password) }
      expect(private_keys.map { |credential| credential.fetch('private_type') }.uniq).to eq(['Metasploit::Credential::SSHKey'])
      # The credential model accepts unencrypted keys; loot retains the original
      # encrypted bytes. Compare public key material through OpenSSL, not text.
      actual = private_keys.map { |credential| OpenSSL::PKey::RSA.new(credential.fetch('private')).public_key.to_der }
      expected = %w[plain encrypted].map do |name|
        bytes = target_exec('target', 'cat', "/etc/salt/pki/collection/#{name}.pub")
        OpenSSL::PKey::RSA.new(bytes).public_key.to_der
      end
      expect(actual.uniq.sort).to eq(expected.sort)
      note = { 'type' => 'SSH Key Password', 'host' => '192.0.2.13', 'data' => { 'ssh_key' => '/etc/salt/pki/collection/encrypted.pem', 'password' => 'module-target-key-passphrase' } }
      expect(snapshot.fetch('decoded_notes')).to include(note)
      addresses = roster.values.map { |entry| entry.fetch('host') } + [target_runtime.fetch('module_endpoints').fetch('target').fetch('host')]
      expect(snapshot.fetch('hosts').map { |host| host.fetch('address') }.sort).to eq(addresses.sort)
    end
  end
end
