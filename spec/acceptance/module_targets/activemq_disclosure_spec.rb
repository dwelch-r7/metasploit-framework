require 'acceptance_spec_helper'
require 'rbconfig'

RSpec.describe 'Genuine legacy ActiveMQ JSP disclosure' do
  include_context 'module target'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/activemq_legacy/disclosure_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-disclosure.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-disclosure-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    expect(stderr).to eq('')
  end

  {
    '/admin/index.jsp' => 'index.jsp',
    '/admin/queues.jsp' => 'queues.jsp',
    'admin/topics.jsp' => 'topics.jsp'
  }.each do |uri, page|
    it "retrieves actual #{page} source with exact bytes twice from #{uri}" do
      expected = target_exec('affected', 'sha256sum', "/opt/activemq/webapps/admin/#{page}").split.first
      2.times do
        before = loot
        output = invoke('affected', uri)
        expect(output).to include('File saved in:')
        created = loot.reject { |row| before.any? { |old| old.fetch('path') == row.fetch('path') } }
        expect(created.length).to eq(1)
        expect(created.first.fetch('sha256')).to eq(expected)
      end
    end
  end

  it 'does not call rendered fixed-version HTML disclosed source on either repetition' do
    2.times { no_loot('fixed', '/admin/index.jsp') }
  end

  it 'does not invent a missing JSP page' do
    no_loot('affected', '/admin/module-target-missing.jsp')
  end

  it 'does not invent JSP source on an unrelated missing endpoint' do
    no_loot('unrelated', '/admin/index.jsp')
  end

  it 'does not store an unrelated genuine HTTP200 index as JSP source' do
    no_loot('unrelated', '/')
  end

  it 'does not store an affected-broker static index as JSP source' do
    no_loot('affected', '/')
  end

  def no_loot(service, uri)
    before = loot
    output = invoke(service, uri, allow_errors: true)
    expect(output).not_to include('File saved in:')
    expect(loot).to eq(before)
  end

  def invoke(service, uri, allow_errors: false)
    console_command('back')
    selected = console_command('use auxiliary/scanner/http/apache_activemq_source_disclosure')
    expect(selected).not_to match(/Failed to load|Unknown command|No results/)
    endpoint = target_runtime.fetch('module_endpoints').fetch(service)
    values = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'TARGETURI' => uri, 'VERBOSE' => true, 'HttpTrace' => true, 'THREADS' => 1 }
    output = console_command("run #{format_datastore_options(values)}")
    # JSP source may legitimately contain Java Exception names. Keep the actual
    # trace and identify Ruby/Framework failures instead of rejecting source data.
    expect(output).not_to match(/undefined method|uninitialized constant|NoMethodError|NameError|TypeError|ArgumentError|RuntimeError|Msf::OptionValidateError/)
    expect(output).not_to include('[-]') unless allow_errors
    expect(output).to include('Auxiliary module execution completed')
    output
  end

  def loot
    code = 'require "digest"; puts "MODULE_TARGET_LOOT=" + JSON.generate(Dir.glob(File.join(Msf::Config.loot_directory, "*")).select { |path| File.file?(path) }.sort.map { |path| {path: path, sha256: Digest::SHA256.file(path).hexdigest} })'
    output = console_command("irb -e '#{code}'")
    JSON.parse(output.match(/^MODULE_TARGET_LOOT=(.*)$/)[1])
  end
end
