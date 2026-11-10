require 'acceptance_spec_helper'
require_relative '../../../test/module_targets/sip/acceptance'

RSpec.describe 'Genuine SIP enumeration and deregistration' do
  include_context 'real SIP targets'

  cases = %w[exposed protected].product(%w[udp tcp], %w[OPTIONS REGISTER]) + %w[OPTIONS REGISTER].map { |method| ['exposed', 'tls', method] }
  cases.each do |service, transport, method|
    it "compares #{service} #{method} enumeration with the actual #{transport} policy twice" do
      enumeration(service, transport, method)
    end
  end

  %w[udp tcp].each do |transport|
    it "keeps the full extension when requested padding is shorter than its digits over #{transport}" do
      enumeration('exposed', transport, 'REGISTER', padding: 0, maximum: 1000)
    end
  end

  %w[1000 1001].each do |account|
    it "attempts to deregister the genuinely registered #{account} account twice and restores operational state" do
      2.times do
        inactive('permissive')
        seeded = native_action('api', operations: [{ role: 'permissive', transport: 'udp', method: 'REGISTER', account: account, expires: 60, password: account == '1001' ? 'module-target-sip-password' : nil }]).first
        expect(seeded.fetch('result').fetch('responses').last.fetch('code')).to eq(200)
        before = state('permissive')
        expect(live_binding?(before, account)).to be(true)
        begin
          output = scan('auxiliary/voip/sip_deregister', 'permissive', { 'CPORT' => 5060, 'SRCADDR' => listener_host, 'EXTENSION' => account, 'DOMAIN' => endpoint('permissive').fetch('host') }, allow_errors: true)
          after = state('permissive')
          aggregate_failures do
            if account == '1000'
              expect(output).to include('de-registered [200 OK]')
              expect(live_binding?(after, account)).to be(false)
              expect(after.fetch('registry')).to eq({})
            else
              expect(output).to include('[401 Unauthorised]')
              same_binding_state(before, after)
            end
            expect(output).not_to include('No response received')
            expect(services).to eq([])
            expect(notes).to eq([])
            expect(credentials).to eq([])
          end
        ensure
          unregister('permissive', account)
        end
      end
    end
  end

  def enumeration(service, transport, method, padding: 4, maximum: 1002)
    protocol = transport == 'udp' ? 'udp' : 'tcp'
    port = transport == 'tls' ? 5061 : 5060
    fullname = transport == 'udp' ? 'auxiliary/scanner/sip/enumerator' : 'auxiliary/scanner/sip/enumerator_tcp'
    accounts = (1000..maximum).map(&:to_s)
    expected = accounts.filter_map do |account|
      code = native_reply(service, transport, method, account).fetch('code')
      [account, code == 200 ? 'Open' : 'Auth'] if [200, 401].include?(code)
    end
    options = { 'MINEXT' => 1000, 'MAXEXT' => maximum, 'PADLEN' => padding, 'METHOD' => method }
    options.merge!('SSL' => true, 'SSLVerifyMode' => 'NONE') if transport == 'tls'
    rows = 2.times.map do
      inactive(service)
      begin
        output = scan(fullname, service, options, port: port)
        snapshot = { output: output, services: services, notes: notes, state: state(service) }
      ensure
        unregister(service)
      end
      snapshot
    end
    rows.each do |snapshot|
      actual = snapshot.fetch(:output).scan(/Found user: (.+) \[(Open|Auth)\]/).map do |user, status|
        [user[/sip:(\d+)@/, 1], status]
      end
      expect(actual.sort).to eq(expected.sort)
      names = expected.map { |account, status| [native_reply(service, transport, method, account).fetch('headers').fetch('to').first.split(';').first, status] }
      expected_services = expected.empty? ? [] : [{ 'address' => endpoint(service).fetch('host'), 'port' => port, 'proto' => protocol, 'name' => 'sip', 'info' => '' }]
      expected_notes = names.map do |user, status|
        { 'address' => endpoint(service).fetch('host'), 'port' => port, 'proto' => protocol, 'ntype' => "Found user: #{user} [#{status}]", 'data' => { 'user' => user } }
      end
      expect(snapshot.fetch(:services).map { |row| row.except('id') }).to eq(expected_services)
      expect(snapshot.fetch(:notes).map { |row| row.except('id') }.sort_by { |row| row.fetch('ntype') }).to eq(expected_notes.sort_by { |row| row.fetch('ntype') })
      expect(live_binding?(snapshot.fetch(:state), '1000')).to eq(method == 'REGISTER')
      expect(live_binding?(snapshot.fetch(:state), '1001')).to be(false)
    end
    expect(rows.last.fetch(:services)).to eq(rows.first.fetch(:services))
    expect(rows.last.fetch(:notes)).to eq(rows.first.fetch(:notes))
    expect(credentials).to eq([])
    inactive(service)
  end
end
