require 'acceptance_spec_helper'
require_relative '../../../test/module_targets/sip/acceptance'

RSpec.describe 'Genuine SIP client authentication capture' do
  include_context 'real SIP targets'

  %w[sipsak sipp].product(%w[default custom]).each do |client, realm|
    it "captures complete native #{client} Digest inputs with #{realm} realm twice and releases the UDP listener" do
      capture_credentials(client, realm)
    end
  end

  it 'preserves a complete nonreplayable Digest credential when the optional John file is omitted' do
    capture_credentials('sipsak', 'custom', file: false)
  end

  it 'challenges a genuine unauthenticated client twice without inventing a credential or file' do
    prefix = File.join(target_runtime.fetch('artifacts'), 'no-auth-capture')
    2.times do
      job = start_listener('JOHNPWFILE' => prefix)
      begin
        result = native_action('sipp', service: 'framework', auth: false, response: 401)
        expect(result.fetch('codes')).to eq([401])
        expect(credentials).to eq([])
        expect(File.exist?(prefix + '_sip')).to be(false)
      ensure
        stop_listener(job)
      end
    end
    expect(console.all_data).not_to include('[-]')
  end

  it 'reports a real exclusive UDP collision and serves a genuine client after that owner releases it' do
    attempted = nil
    collision_output = nil
    begin
      expect(bind_available?).to be(true)
      code = "guard = UDPSocket.new; guard.bind(#{listener_host.inspect}, 5060); framework.instance_variable_set(:@sip_target_exclusive_udp, guard); puts 'SIP_EXCLUSIVE_BIND=' + {address: guard.addr, reuse: guard.getsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR).int, fd: guard.fileno, inode: File.readlink('/proc/self/fd/' + guard.fileno.to_s)}.to_json"
      output = console_command("irb -e #{code.inspect}")
      bound = JSON.parse(output[/^SIP_EXCLUSIVE_BIND=(\{.*\})\r?$/, 1])
      expect(bound.fetch('reuse')).to eq(0)
      expect(bind_available?).to be(false)
      attempted = launch_listener('NONCE' => 'owned-colliding-nonce', 'REALM' => 'module-target-collision')
      wait_for_expect(30, 0.1) { expect(console_command('jobs -l')).to include('No active jobs.') }
      code = %q{guard = framework.instance_variable_get(:@sip_target_exclusive_udp); puts 'SIP_EXCLUSIVE_BIND=' + {address: guard.addr, reuse: guard.getsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR).int, fd: guard.fileno, inode: File.readlink('/proc/self/fd/' + guard.fileno.to_s)}.to_json}
      output = console_command("irb -e #{code.inspect}")
      expect(JSON.parse(output[/^SIP_EXCLUSIVE_BIND=(\{.*\})\r?$/, 1])).to eq(bound)
      collision_output = console.all_data.dup
    ensure
      console_command("jobs -k #{attempted}") if attempted
      code = %q{guard = framework.remove_instance_variable(:@sip_target_exclusive_udp) if framework.instance_variable_defined?(:@sip_target_exclusive_udp); guard&.close; puts 'SIP_EXCLUSIVE_RELEASED'}
      expect(console_command("irb -e #{code.inspect}")).to include('SIP_EXCLUSIVE_RELEASED')
    end
    original = start_listener('NONCE' => 'owned-original-nonce', 'REALM' => 'module-target-original')
    begin
      result = native_action('sipp', service: 'framework', response: 401)
      expect(result.fetch('codes')).to eq([401, 401])
      trace = Base64.decode64(result.fetch('trace_base64'))
      expect(trace).to include('owned-original-nonce', 'module-target-original')
      expect(trace).not_to include('owned-colliding-nonce')
      expect(bind_available?).to be(false)
      digest = digest_fields(trace)
      ha1 = Digest::MD5.hexdigest('1001:module-target-original:module-target-sip-password')
      ha2 = Digest::MD5.hexdigest("REGISTER:#{digest.fetch('uri')}")
      expect(digest.fetch('response')).to eq(Digest::MD5.hexdigest("#{ha1}:owned-original-nonce:#{ha2}"))
      wait_for_expect(30, 0.1) { expect(credentials.length).to eq(1) }
      expect(credentials.first.fetch('username')).to eq('1001')
      expect(credentials.first.fetch('private_data')).to include(digest.fetch('response'))
    ensure
      stop_listener(original)
    end
    expect(collision_output).not_to match(/undefined method|Unknown error:|NoMethodError/)
    expect(collision_output).to include('bad-config: Failed to bind SIP listener')
  end

  def capture_credentials(client, realm, file: true)
    prefix = File.join(target_runtime.fetch('artifacts'), "#{@workspace}-capture-#{client}-#{realm}")
    options = realm == 'custom' ? { 'REALM' => 'module-target-capture', 'NONCE' => '0022446688' } : {}
    options['JOHNPWFILE'] = prefix if file
    snapshots = 2.times.map do
      job = start_listener(options)
      begin
        result = if client == 'sipsak'
                   native_action('sipsak', service: 'framework', transport: 'udp', account: '1001', password: 'module-target-sip-password', expires: 0, expected: nil, symmetric: true)
                 else
                   native_action('sipp', service: 'framework', response: 401)
                 end
        if client == 'sipp'
          expect(result.fetch('codes')).to eq([401, 401])
        else
          expect(result.fetch('exitstatus')).to be_between(0, 3)
          expect(result.fetch('codes')).not_to be_empty
          expect(result.fetch('codes').uniq).to eq([401])
        end
        trace = result['trace_base64'] ? Base64.decode64(result.fetch('trace_base64')) : Base64.decode64(result.fetch('stdout_base64')) + Base64.decode64(result.fetch('stderr_base64'))
        digest = digest_fields(trace)
        expected_realm = realm == 'custom' ? 'module-target-capture' : client_address
        expect(digest.fetch('realm')).to eq(expected_realm)
        expect(digest.fetch('nonce')).to eq(realm == 'custom' ? '0022446688' : '1234')
        expect(digest.fetch('username')).to eq('1001')
        expect(digest.fetch('algorithm', 'MD5')).to eq('MD5')
        ha1 = Digest::MD5.hexdigest("1001:#{digest.fetch('realm')}:module-target-sip-password")
        ha2 = Digest::MD5.hexdigest("REGISTER:#{digest.fetch('uri')}")
        expect(digest.fetch('response')).to eq(Digest::MD5.hexdigest("#{ha1}:#{digest.fetch('nonce')}:#{ha2}"))
        scheme, resource, suffix = digest.fetch('uri').split(':', 3)
        hash = ['$sip$', listener_host, client_address, '1001', digest.fetch('realm'), 'REGISTER', scheme, resource, suffix.to_s, digest.fetch('nonce'), digest.fetch('cnonce', ''), digest.fetch('nc', ''), digest.fetch('qop', ''), digest.fetch('algorithm', 'MD5'), digest.fetch('response')].join('*')
        wait_for_expect(30, 0.1) { expect(credentials.length).to eq(1) }
        { rows: credentials, hash: hash, john: file ? File.binread(prefix + '_sip') : nil }
      ensure
        stop_listener(job)
      end
    end
    aggregate_failures do
      snapshots.each_with_index do |snapshot, index|
        row = snapshot.fetch(:rows).fetch(0)
        expect(row.fetch('username')).to eq('1001')
        expect(row.fetch('private_type')).to eq('Metasploit::Credential::NonreplayableHash')
        expect(row.fetch('jtr_format')).to eq('sip')
        expect(row.fetch('private_data')).to eq(snapshot.fetch(:hash))
        expect(row.fetch('private_data')).not_to eq('module-target-sip-password')
        expect(row.fetch('status')).to eq('Untried')
        expect(row.fetch('address')).to eq(client_address)
        expect(row.fetch('port')).to eq(client == 'sipsak' ? 5099 : 5098)
        expect(row.fetch('proto')).to eq('udp')
        expect(row.fetch('name')).to eq('sip_client')
        expect(row.fetch('module_fullname')).to eq('auxiliary/server/capture/sip')
        if file
          lines = snapshot.fetch(:john).lines
          expect(lines).not_to be_empty
          expect(lines.uniq).to eq(["1001:#{snapshot.fetch(:hash)}\n"])
          previous = index.zero? ? 0 : snapshots.fetch(index - 1).fetch(:john).lines.length
          expect(lines.length).to be > previous
        else
          expect(File.exist?(prefix + '_sip')).to be(false)
        end
      end
      expect(snapshots.last.fetch(:rows).map { |row| row.slice('core_id', 'login_id') }).to eq(snapshots.first.fetch(:rows).map { |row| row.slice('core_id', 'login_id') })
      expect(notes).to eq([])
      expect(console.all_data).not_to include('[-]')
    end
  end

  def client_address
    @native.fetch('client_address')
  end

  def digest_fields(trace)
    authorization = trace[/^Authorization: Digest (.+)\r?$/, 1]
    expect(authorization).not_to be_nil
    authorization.scan(/(\w+)=(?:"([^"]*)"|([^,\s]+))/).to_h { |name, quoted, plain| [name, quoted || plain] }
  end

  def bind_available?
    code = %q{require 'socket'; socket = UDPSocket.new; begin; socket.bind(ARGV[0], Integer(ARGV[1])); puts 'available'; rescue Errno::EADDRINUSE; puts 'in_use'; ensure; socket.close; end}
    target_exec('framework', 'ruby', '-e', code, listener_host, '5060').strip == 'available'
  end

  def launch_listener(options)
    console_command('back')
    expect(console_command('use auxiliary/server/capture/sip')).not_to match(/Failed|Unknown command/)
    values = { 'SRVHOST' => listener_host, 'SRVPORT' => 5060 }.merge(options)
    output = console_command("run -j #{format_datastore_options(values)}")
    expect(output).not_to include('Unknown datastore option:')
    identifier = output[/background job (\d+)/, 1]
    expect(identifier).not_to be_nil
    Integer(identifier)
  end

  def start_listener(options)
    expect(bind_available?).to be(true)
    job = launch_listener(options)
    wait_for_expect(30, 0.1) { expect(bind_available?).to be(false) }
    job
  end

  def stop_listener(job)
    console_command("jobs -k #{job}")
    wait_for_expect(30, 0.1) { expect(bind_available?).to be(true) }
    expect(console_command('jobs -l')).to include('No active jobs.')
  end
end
