require 'acceptance_spec_helper'
require 'nokogiri'
require 'rbconfig'

RSpec.describe 'Native WordPress Multicall credential targets' do
  include_context 'module target'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/wordpress_multicall/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-wordpress-multicall.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-wordpress-multicall-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @accounts = JSON.parse(File.read('test/module_targets/wordpress_multicall/accounts.json'))
  end

  %w[vulnerable fixed modern].each do |service|
    it "finds the actual #{service} administrator twice with the correct password first" do
      2.times do
        output = sweep(service, 'module_admin', [password('module_admin'), 'module-target-wrong-password'])
        expect(output).to include("SUCCESSFUL: module_admin:#{password('module_admin')}")
      end
    end

    it "finds the second password on #{service} using the native batch boundary" do
      output = sweep(service, 'module_admin', ['module-target-wrong-password', password('module_admin')])
      expect(output).to include("SUCCESSFUL: module_admin:#{password('module_admin')}")
      calls = documents(output, 'methodCall').select { |xml| xml.at_xpath('/methodCall/methodName')&.text == 'system.multicall' }
      counts = calls.map { |xml| xml.xpath('/methodCall/params/param/value/array/data/value').size }
      expect(counts).to eq(service == 'vulnerable' ? [2] : [1, 1])
    end

    %w[module_subscriber module_editor].each do |user|
      it "preserves actual #{service} #{user} credentials including XML and Unicode data" do
        output = sweep(service, user, [password(user)])
        expect(output).to include("SUCCESSFUL: #{user}:#{password(user)}")
      end
    end

    it "rejects actual #{service} incorrect passwords through a genuine XML-RPC response" do
      output = sweep(service, 'module_admin', %w[module-target-wrong-password module-target-other-wrong-password])
      expect(output).to include('Starting XML-RPC login sweep')
      expect(output).not_to include('SUCCESSFUL:')
      expect(documents(output, 'methodResponse').any? { |xml| xml.xpath('//member[name="faultCode"]/value/int').map(&:text).include?('403') }).to be(true)
      expect(output).not_to include('HTTP/1.1 500')
    end

    it "rejects an absent #{service} account without inventing valid credentials" do
      output = sweep(service, 'module_target_missing', [password('module_admin')])
      expect(output).to include('Starting XML-RPC login sweep')
      expect(output).not_to include('SUCCESSFUL:', 'HTTP/1.1 500')
      expect(documents(output, 'methodResponse').any? { |xml| xml.xpath('//member[name="faultCode"]/value/int').map(&:text).include?('403') }).to be(true)
    end
  end

  it 'does not identify unrelated real HTTP as WordPress XML-RPC' do
    output = sweep('unrelated', 'module_admin', [password('module_admin')])
    expect(output).to include('Aborting the attack')
    expect(output).not_to include('SUCCESSFUL:', 'Starting XML-RPC login sweep')
  end

  [0, -1, 1701].each do |size|
    it "rejects invalid CHUNKSIZE #{size} before starting authentication" do
      console_command('back')
      console_command('use auxiliary/scanner/http/wordpress_multicall_creds')
      endpoint = target_runtime.fetch('module_endpoints').fetch('vulnerable')
      options = sweep_options('vulnerable', 'module_admin', [password('module_admin')]).merge('RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'CHUNKSIZE' => size)
      output = console_command("run #{format_datastore_options(options)}")
      expect(output).to include('CHUNKSIZE')
      expect(output).not_to include('Starting XML-RPC login sweep', 'SUCCESSFUL:')
      expect(output).not_to match(/Auxiliary failed: ArgumentError|undefined method|Exception/)
    end
  end

  def password(user)
    @accounts.fetch(user).fetch('password')
  end

  def sweep_options(service, user, passwords)
    path = File.join(target_runtime.fetch('artifacts'), 'module-target-multicall-passwords.txt')
    File.write(path, passwords.join("\n") + "\n")
    {
      'SSL' => false, 'TARGETURI' => service == 'modern' ? '/wordpress/' : '/', 'USERNAME' => user,
      'USER_FILE' => nil, 'PASS_FILE' => path, 'CHUNKSIZE' => 2, 'BLOCKEDWAIT' => 0,
      'STOP_ON_SUCCESS' => true, 'DB_ALL_USERS' => false, 'BRUTEFORCE_SPEED' => 5,
      'THREADS' => 1, 'HttpTrace' => true, 'VERBOSE' => true
    }
  end

  def sweep(service, user, passwords)
    output = run_target_module('auxiliary/scanner/http/wordpress_multicall_creds', service, sweep_options(service, user, passwords), allow_errors: true)
    output = output.dup.force_encoding(Encoding::UTF_8)
    expect(output.valid_encoding?).to be(true)
    output
  end

  def documents(output, root)
    output.scan(%r{<\?xml[^?]*\?>\s*<#{root}\b.*?</#{root}>}m).map { |source| Nokogiri::XML(source) }
  end
end
