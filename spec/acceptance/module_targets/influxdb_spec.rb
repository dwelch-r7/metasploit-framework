require 'acceptance_spec_helper'

RSpec.describe 'Genuine InfluxDB enumeration targets' do
  include_context 'module target'

  before(:all) do
    argv = ['python3', '-B', 'test/module_targets/influxdb/native_probe.py']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-influx-result.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-influx-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    expect(stderr).to eq('')
    @native = JSON.parse(stdout)
    expect(@native.fetch('status')).to eq('passed')
  end

  after do
    stdout, stderr, status = Open3.capture3('python3', '-B', 'test/module_targets/influxdb/action.py')
    expect(status.success?).to be(true), stderr
    expect(stderr).to eq('')
    observation = JSON.parse(stdout)
    append('influx-state', observation)
    expect(observation.fetch('states')).to eq(@native.fetch('profiles').fetch('states'))
  end

  reader = { 'USERNAME' => 'module_reader', 'PASSWORD' => 'module-reader-password' }
  points = 'SELECT * FROM "module_metrics"."autogen"."temperature"'
  [
    ['secured', {}, %w[secured databases], 'default root credentials'],
    ['open', { 'USERNAME' => 'absent-user', 'PASSWORD' => 'incorrect-password' }, %w[open databases], 'ignored credentials on the native authentication-disabled server'],
    ['empty', {}, %w[empty databases], 'an actually empty database list'],
    ['secured', reader, %w[reader databases], 'the restricted reader database list'],
    ['prefix', { 'TARGETURI' => '/influx/' }, %w[secured databases], 'the real reverse proxy prefix'],
    ['secured', { 'QUERY' => points }, %w[queries points], 'exact Unicode, quote and timestamp rows'],
    ['prefix', { 'TARGETURI' => '/influx/', 'QUERY' => points }, %w[queries points], 'quoted queries through the real prefix'],
    ['secured', { 'QUERY' => 'SHOW DATABASES; SHOW USERS' }, %w[queries multi], 'multiple native read statements'],
    ['secured', { 'QUERY' => 'SELECT * FROM "module_metrics"."autogen"."absent_measurement"' }, %w[queries no_rows], 'a valid query returning no rows']
  ].each do |service, options, keys, label|
    it "collects exact native JSON twice with #{label}" do
      expected = @native.fetch('profiles').dig(*keys)
      expect(expected).not_to be_nil
      2.times do
        before = loot_files
        output = scan(service, options)
        expect(output).to include('Influx Version: 1.8.10', 'File saved in:')
        files = loot_files - before
        expect(files.length).to eq(1), output
        expect(JSON.parse(File.binread(files.first))).to eq(expected)
        append('influx-loot', service: service, options: options, path: files.first, document: JSON.parse(File.binread(files.first)))
      end
    end
  end

  [
    ['secured', { 'PASSWORD' => 'incorrect-password' }, 'Failed to authenticate. Invalid username/password.', 'wrong credentials'],
    ['secured', { 'USERNAME' => 'absent-user', 'PASSWORD' => 'incorrect-password' }, 'Failed to authenticate. Invalid username/password.', 'an absent account'],
    ['secured', reader.merge('QUERY' => 'SHOW USERS'), 'Unexpected response status 403', 'a genuine admin-only query as the reader'],
    ['secured', { 'QUERY' => 'SELECT FROM' }, 'Unexpected response status 400', 'a genuine query syntax error'],
    ['secured', { 'TARGETURI' => '/missing/' }, 'Unexpected response status 404', 'a missing native API path'],
    ['secured', { 'RPORT' => 8087 }, 'Failed to connect to the influx db server.', 'the owned closed endpoint'],
    ['unrelated', {}, nil, 'unrelated real Apache']
  ].each do |service, options, reason, label|
    it "refuses #{label} twice without query loot" do
      2.times do
        before = loot_files
        output = scan(service, options, allow_errors: true)
        expect(output).to include(reason) if reason
        expect(output).not_to include('File saved in:')
        expect(output).not_to include('Influx Version:') if service == 'unrelated'
        expect(loot_files).to eq(before)
      end
    end
  end

  def scan(service, options, allow_errors: false)
    endpoint = target_runtime.fetch('module_endpoints').fetch(service)
    output = run_target_module(
      'auxiliary/scanner/http/influxdb_enum', service, { 'SSL' => false }.merge(options),
      allow_errors: allow_errors, endpoint_options: { 'RHOST' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port') }
    )
    expect(output).not_to match(/Unknown datastore option|NoMethodError|NameError|TypeError|ArgumentError|RuntimeError/)
    append('influx-calls', service: service, options: options, output: output)
    output
  end

  def loot_files
    Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')]
  end

  def append(name, value)
    File.open(File.join(target_runtime.fetch('artifacts'), "#{name}.jsonl"), 'a') { |file| file.puts(JSON.generate(value)) }
  end
end
