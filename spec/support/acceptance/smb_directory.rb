# frozen_string_literal: true

require 'digest'

RSpec.shared_context 'Samba directory target' do
  include_context 'module target'

  let_it_be(:accounts) { JSON.parse(File.read('test/module_targets/smb_directory/credentials.json')) }
  let_it_be(:policies) { JSON.parse(File.read('test/module_targets/smb_directory/policies.json')) }

  before(:all) do
    profile = self.class.metadata.fetch(:smb_profile)
    argv = ['python3', '-B', 'test/module_targets/smb_directory/native_probe.py', profile]
    output, error, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-probe.json'), output)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-probe-status.json'), JSON.pretty_generate(argv: argv, exitstatus: status.exitstatus, stderr: error))
    expect(status.success?).to be(true), error
    expect(error).to eq('')
    @native = JSON.parse(output)
    expect(sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    expect(console_command('features set smb_session_type true')).not_to match(/Unknown|Failed|\[-\]/)
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/Error|Exception|\[-\]/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-reporting-schema.txt'), sql("SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,ordinal_position"))
  end

  before do |example|
    @workspace = "smb_directory_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(native_users).to eq([])
    @filesystem = filesystem
  end

  after do
    File.write(File.join(target_runtime.fetch('artifacts'), "database-#{@workspace}.json"), JSON.pretty_generate(credentials: credentials, notes: notes, services: services)) if @workspace
    expect(console_command('sessions -K')).not_to match(/Exception|Unknown command/)
    expect(native_users).to eq([])
    expect(filesystem).to eq(@filesystem) if @filesystem
  end

  def native_users(user = 'rpc_admin', expected_exit: 0)
    target_exec('client', 'rpcclient', '--configfile=/opt/module-target-client.conf', '-U', "#{user}%#{accounts.fetch(user)}", 'samba', '-c', 'wkssvc_enumerateusers 1', expected_exit: expected_exit).lines.map(&:strip).reject(&:empty?).sort
  end

  def with_local_users
    holders = []
    %w[local_alice local_bob].each do |user|
      argv = target_runtime.fetch('compose') + ['exec', '-T', 'samba', 'smbclient', '//127.0.0.1/SESSION', '-p', '139', '-m', 'SMB3', '-U', "#{user}%#{accounts.fetch(user)}"]
      input, output, error, waiter = Open3.popen3(*argv)
      holders << [user, input, output, error, waiter]
      Timeout.timeout(5) do
        loop do
          break if native_users.include?("DIRLAB\\#{user}")

          raise "Native holder exited for #{user}" unless waiter.alive?

          sleep 0.1
        end
      end
    end
    expect(native_users).to eq(%w[DIRLAB\local_alice DIRLAB\local_bob])
    yield
  ensure
    Array(holders).reverse_each do |user, input, output, error, waiter|
      input.puts('quit') if waiter.alive?
      input.close
      status = Timeout.timeout(5) { waiter.value }
      File.write(File.join(target_runtime.fetch('artifacts'), "holder-#{@workspace}-#{user}.json"), JSON.pretty_generate(exitstatus: status.exitstatus, stdout: output.read, stderr: error.read))
      output.close
      error.close
      expect(status.success?).to be(true)
    end
    expect(native_users).to eq([])
  end

  def smb_session(user)
    output = gather('smb_login', 'direct', user, { 'CreateSession' => true, 'STOP_ON_SUCCESS' => true })
    session_id = output[/SMB session (\d+) opened/, 1]
    expect(session_id).not_to be_nil, output
    verify_session(session_id)
    session_id
  end

  def verify_session(session_id)
    console.sendline("sessions -i #{session_id}")
    console.recvuntil(/SMB[^\r\n]*> /, timeout: 15)
    begin
      console.sendline('shares')
      output = console.recvuntil(/SMB[^\r\n]*> /, timeout: 15)
      expect(output).to include('SESSION', 'SYSVOL')
      expect(output).not_to match(/\[-\]|\bException\b|Unknown command/)
    ensure
      expect(console_command('background')).to include('Backgrounding session')
    end
  end

  def gather(name, mode, user, options = {}, session_id: nil, negative: false)
    values = if mode == 'session'
               { 'SESSION' => session_id }
             else
               { 'SMBUser' => user, 'SMBPass' => accounts.fetch(user), 'SMBDomain' => 'DIRLAB', 'THREADS' => 1 }.merge(options)
             end
    values = values.merge(options)
    endpoint = mode == 'session' ? {} : target_runtime.fetch('module_endpoints').fetch('samba').then { |target| { 'RHOSTS' => target.fetch('host'), 'RPORT' => target.fetch('port') } }
    console_command('back')
    selected = console_command("use auxiliary/scanner/smb/#{name}")
    expect(selected).not_to match(/Failed to load|Unknown command|No results/)
    output = console_command("run #{format_datastore_options(endpoint.merge('VERBOSE' => true).merge(values))}", timeout: 90)
    # The expected authentication namespace Exceptions::LoginError is not an
    # unhandled Exception. Keep actual stack traces and positive errors strict.
    expect(output).not_to match(/\bException\b|Unknown datastore option|Exploit failed|Auxiliary failed|undefined method|NoMethodError|backtrace|Call stack:|Msf::OptionValidateError/i)
    expect(output).to include('Auxiliary module execution completed')
    expect(output).not_to include('[-]') unless negative
    output
  end

  def filesystem
    code = 'import hashlib,json,pathlib; root=pathlib.Path("/var/lib/module-target"); print(json.dumps({str(p):dict(mode=p.stat().st_mode,uid=p.stat().st_uid,gid=p.stat().st_gid,sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(root.rglob("*")) if p.is_file()},sort_keys=True))'
    JSON.parse(target_exec('samba', 'python3', '-c', code))
  end

  def loot_files
    Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')]
  end

  def credentials
    JSON.parse(sql(<<~SQL))
      SELECT COALESCE(json_agg(row),'[]') FROM (
        SELECT c.id, p.username, secret.data AS password, secret.type AS private_type,
               realm.value AS realm, l.status, host(h.address) AS address, s.port,s.proto,s.name,
               origin.module_full_name
        FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id
        LEFT JOIN metasploit_credential_privates secret ON secret.id=c.private_id
        LEFT JOIN metasploit_credential_realms realm ON realm.id=c.realm_id
        LEFT JOIN metasploit_credential_logins l ON l.core_id=c.id
        LEFT JOIN services s ON s.id=l.service_id LEFT JOIN hosts h ON h.id=s.host_id
        LEFT JOIN metasploit_credential_origin_services origin ON origin.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
        WHERE w.name='#{@workspace}' ORDER BY p.username,c.id
      ) row
    SQL
  end

  def notes
    JSON.parse(sql(<<~SQL))
      SELECT COALESCE(json_agg(row),'[]') FROM (
        SELECT n.id,n.ntype,n.data,host(h.address) AS address,s.port,s.proto,s.name
        FROM notes n JOIN workspaces w ON w.id=n.workspace_id
        LEFT JOIN hosts h ON h.id=n.host_id LEFT JOIN services s ON s.id=n.service_id
        WHERE w.name='#{@workspace}' ORDER BY n.ntype
      ) row
    SQL
  end

  def services
    JSON.parse(sql(<<~SQL))
      SELECT COALESCE(json_agg(row),'[]') FROM (
        SELECT s.id,host(h.address) AS address,s.port,s.proto,s.name,s.info,s.state,s.resource
        FROM services s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id
        WHERE w.name='#{@workspace}' ORDER BY s.name,s.id
      ) row
    SQL
  end

  def verify_ipc_reporting(port = 445)
    rows = services
    child = rows.select { |row| row.fetch('name') == 'dcerpc' }
    expected = { 'address' => target_runtime.fetch('module_endpoints').fetch('samba').fetch('host'), 'port' => port, 'proto' => 'tcp', 'name' => 'dcerpc', 'info' => 'Module: auxiliary/scanner/smb/smb_enumusers_domain', 'state' => 'open', 'resource' => { 'smb' => { 'share' => 'IPC$' } } }
    expect(child.map { |row| row.except('id') }).to eq([expected])
    parent = rows.select { |row| row.fetch('name') == 'smb' }
    expect(parent.length).to eq(1)
    expect(parent.first.values_at('address', 'port', 'proto', 'state', 'resource')).to eq(expected.values_at('address', 'port', 'proto', 'state') + [{}])
    expect(rows).to eq(@reported_ipc_services) if @reported_ipc_services
    @reported_ipc_services = rows
  end

  def sql(query)
    target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end
end
