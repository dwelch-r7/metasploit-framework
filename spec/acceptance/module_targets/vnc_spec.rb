require 'acceptance_spec_helper'

RSpec.describe 'Native VNC authentication targets' do
  include_context 'module target'

  before(:all) do
    [3, 7, 8].each do |version|
      %w[open locked].each do |mode|
        service = "#{mode}3#{version}"
        expect(target_exec(service, 'x11vnc', '-version')).to include('0.9.16')
        passwords = mode == 'open' ? ['unused'] : %w[labvnc42 labvnc42-extra wrong-pass]
        passwords.each do |password|
          report = JSON.parse(target_exec(service, 'python3', '/opt/native_probe.py', '127.0.0.1', '5900', version.to_s, password))
          expect(report.fetch('security_types')).to eq([mode == 'open' ? 1 : 2])
          expect(report.fetch('status')).to eq(password == 'wrong-pass' ? 1 : 0)
          expect(report.values_at('width', 'height', 'desktop')).to eq([320, 240, 'ModuleTargetVNC']) if report.fetch('status').zero?
          File.write(File.join(target_runtime.fetch('artifacts'), "native-#{service}-#{password}.json"), JSON.pretty_generate(report))
        end
      end
    end
  end

  [3, 7, 8].each do |version|
    it "detects actual None security twice over RFB3.#{version}" do
      2.times do
        output = run_target_module('auxiliary/scanner/vnc/vnc_none_auth', "open3#{version}")
        expect(output).to include("VNC server protocol version: 3.#{version}", 'VNC server security types supported: None', 'security types includes None, free access!')
      end
    end

    it "does not report None when RFB3.#{version} requires a password" do
      output = run_target_module('auxiliary/scanner/vnc/vnc_none_auth', "locked3#{version}")
      expect(output).to include("VNC server protocol version: 3.#{version}", 'VNC server security types supported: VNC')
      expect(output).not_to include('free access!')
    end

    it "authenticates the actual eight-byte password and its longer equivalent over RFB3.#{version}" do
      %w[labvnc42 labvnc42-extra].each do |password|
        output = run_target_module('auxiliary/scanner/vnc/vnc_login', "locked3#{version}", login_options(password))
        expect(output).to include('Login Successful:', password)
        expect(output).not_to include('LOGIN FAILED:')
      end
    end

    it "rejects an incorrect password over RFB3.#{version}" do
      output = run_target_module('auxiliary/scanner/vnc/vnc_login', "locked3#{version}", login_options('wrong-pass'), allow_errors: true)
      expect(output).to include('LOGIN FAILED:', 'Authentication failed')
      expect(output).not_to include('Login Successful:')
    end

    it "rejects the single blank-password attempt over RFB3.#{version}" do
      output = run_target_module('auxiliary/scanner/vnc/vnc_login', "locked3#{version}", login_options(nil).merge('BLANK_PASSWORDS' => true), allow_errors: true)
      expect(output).to include('LOGIN FAILED:', 'Authentication failed')
      expect(output).not_to include('Login Successful:')
    end

    it "does not claim password authentication on the open RFB3.#{version} service" do
      output = run_target_module('auxiliary/scanner/vnc/vnc_login', "open3#{version}", login_options('unused'), allow_errors: true)
      expect(output).to include('LOGIN FAILED:', 'No supported authentication method found')
      expect(output).not_to include('Login Successful:')
    end
  end

  it 'does not report None on an unrelated HTTP service' do
    output = run_target_module('auxiliary/scanner/vnc/vnc_none_auth', 'unrelated', { 'ConnectTimeout' => 2 }, allow_errors: true)
    expect(output).to include('Handshake failed:')
    expect(output).not_to include('free access!')
  end

  it 'does not authenticate a password on an unrelated HTTP service' do
    output = run_target_module('auxiliary/scanner/vnc/vnc_login', 'unrelated', login_options('labvnc42').merge('ConnectTimeout' => 2), allow_errors: true)
    expect(output).to include('LOGIN FAILED:')
    expect(output).not_to include('Login Successful:')
  end

  def login_options(password)
    {
      'PASSWORD' => password, 'PASS_FILE' => nil, 'USER_FILE' => nil, 'USERPASS_FILE' => nil,
      'BLANK_PASSWORDS' => false, 'USER_AS_PASS' => false, 'DB_ALL_CREDS' => false,
      'DB_ALL_PASS' => false, 'DB_ALL_USERS' => false, 'STOP_ON_SUCCESS' => true,
      'BRUTEFORCE_SPEED' => 5
    }
  end
end
