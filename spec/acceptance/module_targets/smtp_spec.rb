require 'acceptance_spec_helper'

RSpec.describe 'SMTP module targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  before(:all) do
    %w[vrfy rcpt catchall open_relay].each do |service|
      expect(target_exec(service, 'python3', '/opt/native_probe.py')).to include("relay policy verified: #{service}")
    end
  end

  it 'reads the real Exim banner' do
    output = run_target_module('auxiliary/scanner/smtp/smtp_version', 'vrfy')
    expect(output).to include('SMTP 220 smtp.module-target.test ESMTP Exim 4.95')
  end

  it 'enumerates the actual user through VRFY and rejects the missing user' do
    output = run_target_module('auxiliary/scanner/smtp/smtp_enum', 'vrfy', enum_options)
    expect(output).to include('Trying VRFY module_target received 250', 'Trying VRFY module_target_missing received 550', 'Users found: module_target')
    expect(output).not_to include('Found user: module_target_missing')
  end

  it 'enumerates through RCPT when VRFY and EXPN are unavailable' do
    output = run_target_module('auxiliary/scanner/smtp/smtp_enum', 'rcpt', enum_options)
    expect(output).to include('Trying MAIL FROM: root@smtp.module-target.test / RCPT TO: module_target', 'Users found: module_target')
    expect(output).not_to include('Found user: module_target_missing')
  end

  it 'does not report missing users as present' do
    output = run_target_module('auxiliary/scanner/smtp/smtp_enum', 'vrfy', enum_options.merge('USER_FILE' => 'test/module_targets/smtp/missing-users.txt'))
    expect(output).to include('Trying VRFY module_target_missing received 550')
    expect(output).not_to include('Users found:')
  end

  it 'rejects enumeration results from a catch-all recipient policy' do
    output = run_target_module('auxiliary/scanner/smtp/smtp_enum', 'catchall', enum_options)
    expect(output).to include('RCPT TO: Allowed for random user', 'could not be enumerated (no EXPN, no VRFY, invalid RCPT)')
    expect(output).not_to include('Users found:')
  end

  %w[vrfy open_relay].product([false, true]).each do |service, extended|
    it "tests #{extended ? 'sixteen extended relay forms' : 'standard relaying'} twice against #{service}" do
      2.times do |iteration|
        recipient = "proof-#{extended ? 'extended' : 'standard'}-#{iteration}@recipient.example.test"
        initial_log = target_exec(service, 'cat', '/var/log/exim4/mainlog')
        expect(initial_log).not_to include("<#{recipient}>")
        output = run_target_module('auxiliary/scanner/smtp/smtp_relay', service, {
          'MAILFROM' => 'module-target-relay@sender.example.test', 'MAILTO' => recipient, 'EXTENDED' => extended
        })
        if extended
          outcomes = output.scan(/Test #(\d+) - (?:Potential open SMTP relay detected|No relay detected)/).flatten.map(&:to_i)
          expect(outcomes.sort).to eq((1..16).to_a)
        end
        if service == 'open_relay'
          expect(output).to include(extended ? 'Test #2 - Potential open SMTP relay detected:' : 'Potential open SMTP relay detected:')
          wait_for_expect(20, 0.1) do
            log = target_exec(service, 'cat', '/var/log/exim4/mainlog')
            expect(log).to include("=> :blackhole: <#{recipient}> R=remote_sink")
          end
        else
          expect(output).to include('No relay detected')
          expect(output).not_to include('Potential open SMTP relay detected:')
          log = target_exec(service, 'cat', '/var/log/exim4/mainlog')
          expect(log).not_to include("=> :blackhole: <#{recipient}>")
        end
      end
    end
  end

  def enum_options
    { 'USER_FILE' => 'test/module_targets/smtp/users.txt' }
  end
end
