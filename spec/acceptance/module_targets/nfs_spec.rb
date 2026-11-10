require 'acceptance_spec_helper'
require 'base64'

RSpec.describe 'Genuine user-space NFS and RPC targets' do
  include_context 'module target'

  before(:all) do
    argv = ['python3', '-B', 'test/module_targets/nfs/native_probe.py']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-probe.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-probe-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    expect(stderr).to eq('')
    @native = JSON.parse(stdout)
    expect(@native.fetch('requests').length).to eq(14)
    expect(sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    output = console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)
    expect(output).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-reporting-schema.txt'), sql("SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,ordinal_position"))
  end

  before do |example|
    @workspace = "nfs_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(services).to eq([])
    expect(notes).to eq([])
  end

  %w[open empty unrelated].product(%w[tcp udp]).each do |service, protocol|
    it "enumerates actual #{service} RPC programs twice over #{protocol} with exact service persistence" do
      original = nil
      2.times do
        before = filesystem
        output = gather('auxiliary/scanner/misc/sunrpc_portmapper', service, { 'PROTOCOL' => protocol })
        actual = output.scan(/\b(rpcbind|nfs|mountd)\s+(\d+)\s+(\d+)\s+(\d+)\s+(tcp|udp)\b/).map do |name, program, version, port, transport|
          [name, Integer(program), Integer(version), Integer(port), transport]
        end
        names = { 100000 => 'rpcbind', 100003 => 'nfs', 100005 => 'mountd' }
        maps = native_transport(service, protocol).fetch('maps')
        expected = maps.map { |program, version, transport, port| [names.fetch(program), program, version, port, transport == 6 ? 'tcp' : 'udp'] }
        expect(actual.sort).to eq(expected.sort)
        rows = services
        expected_services = {}
        expected.each do |name, program, version, port, transport|
          expected_services[[port, transport, name]] = { 'address' => endpoint(service).fetch('host'), 'port' => port, 'proto' => transport, 'name' => name, 'info' => "Prog: #{program} Version: #{version} - via portmapper" }
        end
        expect(rows.map { |row| row.except('id') }.sort_by { |row| [row.fetch('port'), row.fetch('proto'), row.fetch('name')] }).to eq(expected_services.values.sort_by { |row| [row.fetch('port'), row.fetch('proto'), row.fetch('name')] })
        expect(rows).to eq(original) if original
        original = rows
        expect(notes).to eq([])
        expect(filesystem).to eq(before)
      end
    end
  end

  configurations = [
    ['open', 'native client address', {}],
    ['empty', 'no exported directories', {}],
    ['unrelated', 'no NFS program', {}],
    ['open', 'an outside address', { 'LHOST' => '192.0.2.3' }],
    ['open', 'a real nonblank client hostname', { 'HOSTNAME' => :native_hostname }],
    ['open', 'disabled location heuristic', { 'Mountable' => false }]
  ]
  configurations.product(%w[tcp udp]).each do |(service, label, options), protocol|
    it "reports #{label} twice over #{protocol} with exact export notes and target state" do
      selected = options.transform_values { |value| value == :native_hostname ? @native.fetch('profiles').fetch('client_hostname') : value }
      original_services = original_notes = nil
      2.times do
        before = filesystem
        output = gather('auxiliary/scanner/nfs/nfsmount', service, { 'PROTOCOL' => protocol, 'LHOST' => listener_host }.merge(selected), allow_errors: service == 'unrelated')
        if service == 'unrelated'
          expect(output).to include('Program not available')
          expect(output).not_to include('NFS Export:')
          expect(services).to eq([])
          expect(notes).to eq([])
        else
          exports = native_transport(service, protocol).fetch('exports')
          parsed = output.scan(/(Mountable NFS Export|NFS Export):\s+(\S+)\s+\[([^\r\n]*)\]/).to_h do |kind, path, groups|
            [path, { 'mountable' => kind == 'Mountable NFS Export', 'groups' => groups }]
          end
          allowed = if selected['Mountable'] == false
                      exports.map(&:first)
                    elsif selected['LHOST'] == '192.0.2.3'
                      %w[/exports/open /exports/read-only]
                    else
                      %w[/exports/open /exports/read-only /exports/network /exports/netmask]
                    end
          expected = exports.to_h { |path, groups| [path, { 'mountable' => allowed.include?(path), 'groups' => groups.join(', ') }] }
          expect(parsed).to eq(expected)
          rows = services
          expect(rows.map { |row| row.except('id') }).to eq([{ 'address' => endpoint(service).fetch('host'), 'port' => 2049, 'proto' => protocol, 'name' => 'nfsd', 'info' => 'NFS Daemon 100005 v1' }])
          expected_notes = if exports.empty?
                             expect(output).to include('No exported directories')
                             []
                           else
                             binary_exports = exports.map { |path, groups| [path.b, groups.map(&:b)] }
                             [{ 'address' => endpoint(service).fetch('host'), 'port' => 2049, 'proto' => protocol, 'ntype' => 'nfs.exports', 'data' => [Marshal.dump(exports: binary_exports)].pack('m') }]
                           end
          current_notes = notes
          expect(current_notes.map { |row| row.except('id') }).to eq(expected_notes)
          expect(rows).to eq(original_services) if original_services
          expect(current_notes).to eq(original_notes) if original_notes
          original_services = rows
          original_notes = current_notes
        end
        expect(filesystem).to eq(before)
      end
    end
  end

  def endpoint(service)
    target_runtime.fetch('module_endpoints').fetch(service)
  end

  def native_transport(service, protocol)
    @native.fetch('profiles').fetch(service).fetch('transports').fetch(protocol)
  end

  def gather(fullname, service, options = {}, allow_errors: false)
    output = run_target_module(fullname, service, { 'THREADS' => 1 }.merge(options), allow_errors: allow_errors)
    expect(output).not_to include('Unknown datastore option:')
    output
  end

  def filesystem
    code = 'import hashlib,json,pathlib; root=pathlib.Path("/exports"); print(json.dumps({str(p):dict(mode=p.stat().st_mode,uid=p.stat().st_uid,gid=p.stat().st_gid,sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(root.rglob("*")) if p.is_file()},sort_keys=True))'
    JSON.parse(target_exec('open', 'python3', '-c', code))
  end

  def services
    query = <<~SQL
      SELECT COALESCE(json_agg(row),'[]') FROM (
        SELECT s.id,host(h.address) AS address,s.port,s.proto,s.name,s.info
        FROM services s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id
        WHERE w.name='#{@workspace}' ORDER BY s.port,s.proto,s.name
      ) row
    SQL
    JSON.parse(sql(query))
  end

  def notes
    query = <<~SQL
      SELECT COALESCE(json_agg(row),'[]') FROM (
        SELECT n.id,host(h.address) AS address,s.port,s.proto,n.ntype,n.data
        FROM notes n LEFT JOIN hosts h ON h.id=n.host_id LEFT JOIN services s ON s.id=n.service_id
        JOIN workspaces w ON w.id=n.workspace_id WHERE w.name='#{@workspace}' ORDER BY n.id
      ) row
    SQL
    JSON.parse(sql(query))
  end

  def sql(query)
    target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end
end
