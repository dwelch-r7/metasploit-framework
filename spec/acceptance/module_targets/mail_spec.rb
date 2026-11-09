require 'acceptance_spec_helper'

RSpec.describe 'Native POP3 and IMAP targets' do
  include_context 'module target'

  before(:all) do
    @mail_preflight = mail_probe('before')
  end

  after(:all) do
    if @mail_preflight
      final = mail_probe('after', '--read-only')
      @mail_preflight.each do |service, profile|
        expect(final.fetch(service).values_at('messages', 'message_sha256')).to eq(profile.values_at('messages', 'message_sha256'))
      end
    end
  end

  %w[pop3 pop3s].each do |service|
    it "reads the actual POP3 greeting over #{service}" do
      output = run_target_module('auxiliary/scanner/pop3/pop3_version', service, tls_options(service))
      expect(output).to include("POP3 #{@mail_preflight.fetch(service).fetch('banner')}")
    end

    it "authenticates the configured #{service} user on successive connections" do
      2.times do
        output = run_pop_login(service)
        expect(output).to include("Success: 'module_target:module-target-password' '+OK Logged in.")
        expect(output).not_to include('Failed:', 'Could not connect:')
      end
    end

    it "rejects an incorrect #{service} password" do
      output = run_pop_login(service, { 'PASSWORD' => 'wrong-password' }, allow_errors: true)
      expect(output).to include("Failed: 'module_target:wrong-password'")
      expect(output).not_to include('Success:')
    end
  end

  %w[imap imaps].each do |service|
    it "reads the actual IMAP greeting over #{service}" do
      output = run_target_module('auxiliary/scanner/imap/imap_version', service, tls_options(service))
      expect(output).to include("IMAP #{@mail_preflight.fetch(service).fetch('banner')}")
    end
  end

  it 'rejects a username absent from the native password file' do
    output = run_pop_login('pop3', { 'USERNAME' => 'missing-user' }, allow_errors: true)
    expect(output).to include("Failed: 'missing-user:module-target-password'")
    expect(output).not_to include('Success:')
  end

  it 'rejects one blank password candidate' do
    output = run_pop_login('pop3', { 'PASSWORD' => nil, 'BLANK_PASSWORDS' => true }, allow_errors: true)
    expect(output).to include("Failed: 'module_target:'")
    expect(output).not_to include('Success:')
  end

  it 'rejects the anonymous credential candidate' do
    output = run_pop_login('pop3', { 'USERNAME' => nil, 'PASSWORD' => nil, 'ANONYMOUS_LOGIN' => true }, allow_errors: true)
    expect(output).to include('Failed:')
    expect(output).not_to include('Success:')
  end

  it 'refuses cleartext authentication under the real TLS-required policy' do
    output = run_pop_login('required', {}, allow_errors: true)
    expect(output).to include('Failed:', 'TLS')
    expect(output).not_to include('Success:')
  end

  it 'does not authenticate POP3 against the actual IMAP listener' do
    output = run_pop_login('imap', {}, allow_errors: true)
    expect(output).to include('Failed:', '* OK [CAPABILITY')
    expect(output).not_to include('Success:')
  end

  def tls_options(service)
    { 'SSL' => %w[pop3s imaps].include?(service), 'SSLVerifyMode' => 'NONE' }
  end

  def run_pop_login(service, options = {}, allow_errors: false)
    values = {
      'USERNAME' => 'module_target', 'PASSWORD' => 'module-target-password',
      'USER_FILE' => nil, 'PASS_FILE' => nil, 'USERPASS_FILE' => nil,
      'BLANK_PASSWORDS' => false, 'ANONYMOUS_LOGIN' => false, 'USER_AS_PASS' => false,
      'DB_ALL_CREDS' => false, 'DB_ALL_USERS' => false, 'DB_ALL_PASS' => false,
      'BRUTEFORCE_SPEED' => 5, 'STOP_ON_SUCCESS' => true
    }.merge(tls_options(service)).merge(options)
    run_target_module('auxiliary/scanner/pop3/pop3_login', service, values, allow_errors: allow_errors)
  end

  def mail_probe(label, *arguments)
    argv = ['python3', 'test/module_targets/mail/native_probe.py', *arguments]
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), "native-mail-#{label}.json"), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), "native-mail-#{label}-command.json"), JSON.pretty_generate(argv: argv, error: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    profiles = JSON.parse(stdout).fetch('profiles')
    expect(profiles.keys.sort).to eq(%w[imap imaps pop3 pop3s required])
    profiles
  end
end
