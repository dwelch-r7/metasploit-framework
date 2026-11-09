require 'acceptance_spec_helper'
require 'rbconfig'

RSpec.describe 'Native WordPress discovery and authentication targets' do
  include_context 'module target'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/wordpress/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-wordpress.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-wordpress-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @profiles = JSON.parse(stdout).fetch('profiles')
  end

  %w[root prefix plain blocked].each do |service|
    it "discovers actual #{service} versions, accessible components and the published author" do
      output = discover(service)
      expect(output).to include("Detected Wordpress #{@profiles.fetch(service).fetch('version')}")
      @profiles.fetch(service).fetch('themes').each do |slug, data|
        expect(output).to include("Detected theme: #{slug} version #{data.fetch('version')}")
      end
      if service == 'blocked'
        expect(output).not_to include('Detected plugin: akismet')
      else
        expect(output).to include("Detected plugin: akismet version #{@profiles.fetch(service).fetch('remote_versions').fetch('akismet')}")
      end
      expect(output).to include('Detected user: Module café author with username: module_author')
      expect(output).not_to include('Detected user: module_admin', 'Detected user: module_subscriber', 'Detected theme: module-target-missing', 'Detected plugin: module-target-missing')
    end
  end

  it 'uses the normal component shortlists when EXPLOITABLE is false' do
    output = discover('root', 'EXPLOITABLE' => false)
    expect(output).to include('Detected plugin: akismet version 5.5', 'Detected theme: twentytwentyfive version 1.3')
  end

  it 'honors version-only selection without enumerating components or users' do
    output = discover('root', 'THEMES' => false, 'PLUGINS' => false, 'USERS' => false)
    expect(output).to include('Detected Wordpress 6.8.3')
    expect(output).not_to include('Detected plugin:', 'Detected theme:', 'Detected user:')
  end

  it 'handles deliberately empty component lists without inventing discoveries' do
    output = discover('root', 'EXPLOITABLE_THEMES' => fixture_path('empty.txt'), 'EXPLOITABLE_PLUGINS' => fixture_path('empty.txt'), 'USERS' => false)
    expect(output).to include('Finished scanning themes', 'Finished scanning plugins')
    expect(output).not_to include('Detected plugin:', 'Detected theme:')
  end

  it 'does not discover WordPress on unrelated real HTTP' do
    expect(discover('unrelated')).not_to include('Detected Wordpress', 'Detected user:', 'Detected theme:', 'Detected plugin:')
  end

  %w[root prefix].each do |service|
    it "authenticates the actual #{service} author on two consecutive executions" do
      2.times do
        expect(html_login(service)).to include("SUCCESSFUL login for 'module_author' : 'module-target-author-password'")
      end
    end

    it "authenticates the #{service} editor with XML metacharacters and Unicode in the password" do
      expect(html_login(service, 'USERNAME' => 'module_editor', 'PASSWORD' => 'module-target-&<café>')).to include("SUCCESSFUL login for 'module_editor'")
    end

    {
      'wrong' => { 'PASSWORD' => 'module-target-wrong-password' },
      'blank' => { 'PASSWORD' => nil, 'BLANK_PASSWORDS' => true },
      'missing account' => { 'USERNAME' => 'module_target_missing' }
    }.each do |label, options|
      it "rejects a #{label} #{service} HTML login" do
        output = html_login(service, options)
        expect(output).to include("Failed to login as '#{options.fetch('USERNAME', 'module_author')}'")
        expect(output).not_to include('SUCCESSFUL login')
      end
    end

    it "validates an existing #{service} username without attempting authentication" do
      output = html_login(service, 'BRUTEFORCE' => false, 'VALIDATE_USERS' => true)
      expect(output).to include("Username: 'module_author' - is VALID", 'Found 1 valid user')
      expect(output).not_to include('SUCCESSFUL login')
    end

    it "rejects a nonexistent #{service} username during validation" do
      output = html_login(service, 'BRUTEFORCE' => false, 'VALIDATE_USERS' => true, 'USERNAME' => 'module_target_missing')
      expect(output).to include("Invalid Username: 'module_target_missing'")
      expect(output).not_to include('is VALID', 'SUCCESSFUL login')
    end

    it "enumerates the actual published #{service} author and stores exact username loot" do
      output = html_login(service, 'BRUTEFORCE' => false, 'ENUMERATE_USERNAMES' => true, 'RANGE_START' => 2, 'RANGE_END' => 2)
      expect(output).to include("Found user 'module_author' with id 2")
      paths = output.scan(/Usernames stored in: ([^\r\n]+)/).flatten.map(&:strip)
      expect(paths.size).to eq(1)
      expect(File.expand_path(paths.first)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
      expect(File.binread(paths.first)).to eq('module_author')
    end

    it "does not invent an author for the absent #{service} identifier" do
      output = html_login(service, 'BRUTEFORCE' => false, 'ENUMERATE_USERNAMES' => true, 'RANGE_START' => 5, 'RANGE_END' => 5)
      expect(output).not_to include('Found user', 'Usernames stored in:')
    end
  end

  it 'does not authenticate or enumerate unrelated actual HTTP through the HTML module' do
    output = html_login('unrelated')
    expect(output).to include('does not seem to be WordPress site')
    expect(output).not_to include('SUCCESSFUL login', 'Found user')
  end

  %w[root prefix].each do |service|
    it "authenticates the #{service} XML-RPC administrator twice" do
      2.times { expect(rpc_login(service)).to include("Success: 'module_admin:module-target-password'") }
    end

    {
      'subscriber' => ['module_subscriber', 'module-target-subscriber-password'],
      'special editor' => ['module_editor', 'module-target-&<café>']
    }.each do |label, (user, password)|
      it "recognizes the valid #{service} #{label} credentials despite native user-list permission refusal" do
        expect(rpc_login(service, 'USERNAME' => user, 'PASSWORD' => password)).to include("Success: '#{user}:#{password}'")
      end
    end

    {
      'wrong password' => { 'PASSWORD' => 'module-target-wrong-password' },
      'missing account' => { 'USERNAME' => 'module_target_missing' }
    }.each do |label, options|
      it "rejects #{service} XML-RPC with a #{label}" do
        output = rpc_login(service, options)
        expect(output).to include('Failed:')
        expect(output).not_to include('Success:')
      end
    end
  end

  %w[blocked unrelated].each do |service|
    it "does not authenticate the #{service} XML-RPC endpoint" do
      output = rpc_login(service)
      expect(output).to include('Unable to locate WordPress XML-RPC endpoint')
      expect(output).not_to include('Success:', 'Starting XML-RPC login sweep')
    end
  end

  def fixture_path(name)
    "/usr/src/metasploit-framework/test/module_targets/wordpress/#{name}"
  end

  def base_options(service)
    { 'SSL' => false, 'TARGETURI' => service == 'prefix' ? '/wordpress/' : '/', 'THREADS' => 1 }
  end

  def discover(service, options = {})
    lists = {
      'EXPLOITABLE_THEMES' => fixture_path('themes.txt'), 'THEMES_FILE' => fixture_path('themes.txt'),
      'EXPLOITABLE_PLUGINS' => fixture_path('plugins.txt'), 'PLUGINS_FILE' => fixture_path('plugins.txt')
    }
    native_output(run_target_module('auxiliary/scanner/http/wordpress_scanner', service, base_options(service).merge(lists).merge(options), allow_errors: true))
  end

  def credentials
    {
      'USER_FILE' => nil, 'PASS_FILE' => nil, 'USERPASS_FILE' => nil, 'USER_AS_PASS' => false,
      'DB_ALL_CREDS' => false, 'DB_ALL_USERS' => false, 'DB_ALL_PASS' => false, 'STOP_ON_SUCCESS' => true, 'BRUTEFORCE_SPEED' => 5
    }
  end

  def html_login(service, options = {})
    defaults = credentials.merge('USERNAME' => 'module_author', 'PASSWORD' => 'module-target-author-password', 'BLANK_PASSWORDS' => false,
                                 'VALIDATE_USERS' => false, 'ENUMERATE_USERNAMES' => false, 'BRUTEFORCE' => true)
    native_output(run_target_module('auxiliary/scanner/http/wordpress_login_enum', service, base_options(service).merge(defaults).merge(options), allow_errors: true))
  end

  def rpc_login(service, options = {})
    defaults = credentials.merge('USERNAME' => 'module_admin', 'PASSWORD' => 'module-target-password')
    native_output(run_target_module('auxiliary/scanner/http/wordpress_xmlrpc_login', service, base_options(service).merge(defaults).merge(options), allow_errors: true))
  end

  def native_output(output)
    output = output.dup.force_encoding(Encoding::UTF_8)
    expect(output.valid_encoding?).to be(true)
    output
  end
end
