require 'acceptance_spec_helper'
require 'net/http'
require 'rbconfig'

RSpec.describe 'Native MQTT authentication targets' do
  include_context 'module target'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/mqtt/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-mqtt-preflight.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-mqtt-preflight-command.json'), JSON.pretty_generate(argv: argv, error: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    profiles = JSON.parse(stdout).fetch('profiles')
    expect(profiles.keys.sort).to eq(%w[auth open prefix tls])
    expect(target_exec('unrelated', 'httpd', '-v')).to include('Apache/2.4.62')
    endpoint = target_endpoint('unrelated')
    client = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    client.read_timeout = 3
    response = client.get('/')
    expect(response.code).to eq('200')
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-unrelated-http.json'), JSON.pretty_generate(status: response.code, headers: response.to_hash, body: response.body))
  end

  it 'detects actual anonymous access without claiming arbitrary credentials are authenticated' do
    output = run_mqtt('open', 'USERNAME' => 'unused-user', 'PASSWORD' => 'unused-password')
    expect(output).to include('Does not require authentication')
    expect(output).not_to include('Starting MQTT login sweep', 'MQTT Login Successful:')
  end

  %w[auth tls].each do |service|
    it "authenticates the configured #{service} user on successive connections" do
      2.times do
        output = run_mqtt(service)
        expect(output).to include('MQTT Login Successful: lab-mqtt-user/lab-mqtt-password')
        expect(output).not_to include('Does not require authentication', 'MQTT LOGIN FAILED:')
      end
    end

    it "rejects an incorrect password on #{service}" do
      output = run_mqtt(service, { 'PASSWORD' => 'wrong-password' }, allow_errors: true)
      expect(output).to include('MQTT LOGIN FAILED:', 'Failed Connection (5)')
      expect(output).not_to include('MQTT Login Successful:', 'Does not require authentication')
    end
  end

  it 'rejects a username absent from the native password file' do
    output = run_mqtt('auth', { 'USERNAME' => 'missing-user' }, allow_errors: true)
    expect(output).to include('MQTT LOGIN FAILED:', 'Failed Connection (5)')
    expect(output).not_to include('MQTT Login Successful:', 'Does not require authentication')
  end

  it 'rejects one blank password candidate' do
    output = run_mqtt('auth', { 'PASSWORD' => nil, 'BLANK_PASSWORDS' => true }, allow_errors: true)
    expect(output).to include('MQTT LOGIN FAILED:', 'Failed Connection (5)')
    expect(output).not_to include('MQTT Login Successful:', 'Does not require authentication')
  end

  it 'rejects the ordinary generated client ID under the actual prefix policy' do
    output = run_mqtt('prefix', { 'CLIENT_ID' => nil }, allow_errors: true)
    expect(output).to include('MQTT LOGIN FAILED:', 'Failed Connection (5)')
    expect(output).not_to include('MQTT Login Successful:', 'Does not require authentication')
  end

  it 'accepts the explicit prefix and reports genuine anonymous access' do
    output = run_mqtt('prefix', 'CLIENT_ID' => 'module-target-good')
    expect(output).to include('Does not require authentication')
    expect(output).not_to include('Starting MQTT login sweep', 'MQTT Login Successful:')
  end

  it 'does not identify unrelated actual HTTP as MQTT authentication success' do
    output = run_mqtt('unrelated', {}, allow_errors: true)
    expect(output).not_to include('MQTT Login Successful:', 'Does not require authentication')
  end

  def run_mqtt(service, options = {}, allow_errors: false, **datastore_options)
    values = {
      'USERNAME' => 'lab-mqtt-user', 'PASSWORD' => 'lab-mqtt-password',
      'CLIENT_ID' => 'module-target-framework', 'READ_TIMEOUT' => 2,
      'USER_FILE' => nil, 'PASS_FILE' => nil, 'USERPASS_FILE' => nil,
      'BLANK_PASSWORDS' => false, 'USER_AS_PASS' => false, 'STOP_ON_SUCCESS' => true,
      'DB_ALL_CREDS' => false, 'DB_ALL_USERS' => false, 'DB_ALL_PASS' => false,
      'BRUTEFORCE_SPEED' => 5, 'SSL' => service == 'tls', 'SSLVerifyMode' => 'NONE'
    }.merge(options).merge(datastore_options)
    # Omission selects the real generated ID; a blank argument fails validation.
    values.delete('CLIENT_ID') if values['CLIENT_ID'].nil?
    run_target_module('auxiliary/scanner/mqtt/connect', service, values, allow_errors: allow_errors)
  end
end
