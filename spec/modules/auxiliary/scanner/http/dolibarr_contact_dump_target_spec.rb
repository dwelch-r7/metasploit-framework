require 'acceptance_spec_helper'
require 'net/http'
require 'csv'
require 'digest'

RSpec.describe 'Genuine Dolibarr contact collection', acceptance: true, order: :defined do
  include_context 'module target'

  before(:all) do
    @unrelated = ENV['DOLIBARR_UNRELATED'] == 'true'
    @prefix = ENV.fetch('DOLIBARR_PREFIX', '')
    @version = ENV['DOLIBARR_VERSION']
    @lookup = ENV['DOLIBARR_LOOKUP_ENABLE'] == 'true'
    @exposed = @version == '16.0.4'
    @birth = target_exec('target', 'cat', '/proc/1/stat').split(') ', 2).last.split.fetch(19)
    @config_sha256 = target_exec('target', 'sha256sum', '/opt/dolibarr/htdocs/conf/conf.php').split.first unless @unrelated
    verify_artifacts unless @unrelated
    native_control('before')
  end

  after do
    %w[sessions jobs].each do |kind|
      expect(console_command("irb -e 'puts \"DOLIBARR_IDLE=\" + framework.#{kind}.keys.to_json'")).to include('DOLIBARR_IDLE=[]')
    end
    expect(target_exec('target', 'cat', '/proc/1/stat').split(') ', 2).last.split.fetch(19)).to eq(@birth)
  end

  after(:all) do
    native_control('after') if @birth
    verify_artifacts if @birth && !@unrelated
    (@unrelated ? %w[target framework] : %w[target database framework]).each do |role|
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/memory.events')).to include("oom 0\n", "oom_kill 0\n")
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/pids.events').strip).to eq('max 0')
    end
  end

  it 'checks twice without inventing product detection or creating loot' do
    2.times do
      before = loot_files
      rows = state.fetch('contacts') unless @unrelated
      output = owning_call(action: 'check')
      expected = if @unrelated
                   'Cannot reliably check exploitability.'
                 elsif @exposed
                   'The target appears to be vulnerable.'
                 else
                   'The target is not exploitable.'
                 end
      expect(output).to include(expected)
      expect(loot_files).to eq(before)
      expect(state.fetch('contacts')).to eq(rows) unless @unrelated
    end
  end

  if ENV['DOLIBARR_UNRELATED'] == 'true'
    it 'rejects an unrelated endpoint twice without exporting an error page' do
      collect_twice(:json)
    end
  else
    it 'exports complete native contact objects and connection metadata twice' do
      collect_twice(:json)
    end

    it 'preserves quoted Unicode and multiline scalar CSV values twice' do
      collect_twice(:csv)
    end

    it 'handles an actually empty contact database twice' do
      expect(state('empty').fetch('contacts')).to eq([])
      collect_twice(:json)
    ensure
      restored = state('restore')
      expect(restored.fetch('contacts').length).to eq(3)
    end

    it 'collects again after the original models restore the deleted contacts' do
      expect(state.fetch('contacts').length).to eq(3)
      collect_twice(:csv)
    end
  end

  def journal(name, record)
    File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |file| file.puts(JSON.generate(record)) }
  end

  def state(action = 'state')
    JSON.parse(target_exec('target', 'php', '-d', 'extension=/runtime/mysqli.so', '-d', 'date.timezone=UTC', '/lab/state.php', action))
  end

  def verify_artifacts
    root = File.expand_path('../../../../..', __dir__)
    catalog = JSON.parse(File.read(File.join(root, 'test/module_targets/dolibarr/vendor.json')))
    expect(target_exec('target', 'sha256sum', '/opt/dolibarr/htdocs/conf/conf.php').split.first).to eq(@config_sha256)
    record = catalog.fetch('versions').fetch(@version)
    record.fetch('source_files').each do |path, entry|
      expect(target_exec('target', 'sha256sum', '/opt/dolibarr/' + path).split.first).to eq(entry.fetch('sha256'))
    end
    expect(target_exec('target', 'sha256sum', '/runtime/mysqli.so').split.first).to eq(catalog.fetch('runtime').fetch('mysqli_sha256'))
    current = state
    expect(current).to include('version' => @version, 'php' => '5.6.40', 'mysqli' => true, 'ticket_enabled' => @lookup, 'lookup_enabled' => @lookup)
  end

  def native_request(path, phase, fields: nil, cookies: nil, redirects: 0)
    endpoint = target_endpoint('target')
    request = fields ? Net::HTTP::Post.new(path) : Net::HTTP::Get.new(path)
    if fields
      request.set_form_data(fields)
      request['Referer'] = "http://#{endpoint.fetch('host')}:#{endpoint.fetch('port')}#{@prefix}/"
      request['Origin'] = "http://#{endpoint.fetch('host')}:#{endpoint.fetch('port')}"
    end
    request['Cookie'] = cookies.map { |name, value| "#{name}=#{value}" }.join('; ') if cookies && !cookies.empty?
    response = Net::HTTP.start(endpoint.fetch('host'), endpoint.fetch('port'), nil, open_timeout: 5, read_timeout: 12) { |http| http.request(request) }
    response.get_fields('set-cookie').to_a.each do |header|
      name, value = header.split(';', 2).first.split('=', 2)
      cookies[name] = value if cookies
    end
    journal('native-http.jsonl', phase: phase, path: path, method: request.method, cookie_jar: !cookies.nil?, status: response.code.to_i, body: response.body.to_s, sha256: Digest::SHA256.hexdigest(response.body.to_s))
    if response.is_a?(Net::HTTPRedirection)
      raise 'Too many native redirects' if redirects >= 5

      location = URI.join("http://#{endpoint.fetch('host')}:#{endpoint.fetch('port')}#{path}", response.fetch('location'))
      expect([location.host, location.port]).to eq([endpoint.fetch('host'), endpoint.fetch('port')])
      return native_request(location.request_uri, phase, cookies: cookies, redirects: redirects + 1)
    end
    response
  end

  def native_contacts(email, phase)
    native_request(@prefix + '/public/ticket/ajax/ajax.php?' + URI.encode_www_form(action: 'getContacts', email: email), phase)
  end

  def native_control(phase)
    root = native_request(@prefix + '/', phase)
    expect(root.code.to_i).to eq(200)
    if @unrelated
      expect(root.body).to include('Unrelated static site')
      expect(native_contacts('%', phase).code.to_i).to eq(404)
      return
    end
    before = state
    cookies = {}
    protected_page = native_request(@prefix + '/user/card.php?id=1', phase, cookies: cookies)
    expect(protected_page.body).to include('name="username"')
    ['wrong-module-password', 'ModuleAdminPassword1!'].each do |password|
      login = native_request(@prefix + '/', phase, cookies: cookies)
      token = login.body[/name="token"\s+value="([^"]+)"/, 1]
      expect(token).not_to be_nil
      native_request(@prefix + '/', phase, fields: { token: token, actionlogin: 'login', username: 'moduleadmin', password: password }, cookies: cookies)
      card = native_request(@prefix + '/user/card.php?id=1', phase, cookies: cookies)
      if password == 'wrong-module-password'
        expect(card.body).to include('name="username"')
      else
        expect(card.body).to include('SuperAdmin')
        expect(card.body).not_to include('name="username"')
      end
    end
    if @exposed || @lookup
      expect(JSON.parse(native_contacts('absent@example.invalid', phase).body).fetch('contacts')).to eq([])
      known = JSON.parse(native_contacts('alpha@example.invalid', phase).body).fetch('contacts')
      alpha = before.fetch('contacts').find { |row| row.fetch('email') == 'alpha@example.invalid' }
      expect(known.length).to eq(1)
      %w[firstname lastname email note_public note_private].each { |key| expect(known.first.fetch(key)).to eq(alpha.fetch(key)) }
      domain = JSON.parse(native_contacts('%@example.invalid', phase).body).fetch('contacts')
      expect(domain.map { |contact| contact.fetch('email') }.sort).to eq(%w[alpha@example.invalid beta@example.invalid])
    else
      denied = native_contacts('alpha@example.invalid', phase)
      expect(denied.code.to_i).to eq(200)
      expect(Digest::SHA256.hexdigest(denied.body)).to eq('272a194d1e167c5eca7f95f7491d9c5bca2753180bc3de9e05cbd6ef7bb93040')
    end
    expect(state.fetch('contacts')).to eq(before.fetch('contacts'))
  end

  def loot_files
    Dir[File.join(target_runtime.fetch('artifacts'), 'msf-config', 'loot', '*')].select { |path| File.file?(path) }.sort
  end

  def owning_call(action: 'run')
    output = nil
    begin
      output = run_target_module('auxiliary/scanner/http/dolibarr_16_contact_dump', 'target', { 'TARGETURI' => @prefix + '/', 'THREADS' => 1, 'HttpClientTimeout' => 8 }, action: action, allow_errors: true)
    ensure
      journal('owning-calls.jsonl', action: action, output: (output || console.all_data).dup.force_encoding(Encoding::UTF_8), wrapper_returned: !output.nil?)
    end
    output
  end

  def collect_twice(format)
    2.times do
      rows = state.fetch('contacts') unless @unrelated
      response = native_contacts('%', 'before-owning-call')
      expect(response.code.to_i).to eq(@unrelated ? 404 : 200)
      expected = (@exposed || @lookup) ? JSON.parse(response.body) : nil
      before = loot_files
      output = owning_call
      created = loot_files - before
      if @exposed && !rows.empty?
        expect(created.length).to eq(2), output
        json = created.find { |path| File.binread(path).start_with?('{') }
        expect(json).not_to be_nil
        csv = (created - [json]).first
        expect(JSON.parse(File.binread(json))).to eq(expected)
        expect(output).to include("Found #{rows.length} contacts.", 'Database type: mysqli', 'Database name: dolibarr', 'Database user: module_app', 'Database host: database', 'Database port: 3306')
        if format == :csv
          table = CSV.parse(File.binread(csv).force_encoding(Encoding::UTF_8), headers: true)
          headers = expected.fetch('contacts').first.keys - ['db']
          expect(table.headers).to eq(headers)
          values = expected.fetch('contacts').map do |contact|
            headers.map { |key| contact[key].is_a?(String) || contact[key].is_a?(Integer) ? contact[key].to_s : '' }
          end
          expect(table.map(&:fields)).to eq(values)
        end
        created.each { |path| journal('verified-loot.jsonl', path: path, bytes: File.size(path), sha256: Digest::SHA256.file(path).hexdigest, format: format) }
      else
        expect(created).to eq([]), output
        expect(output).not_to include('File saved in:', 'Found 3 contacts.')
      end
      expect(state.fetch('contacts')).to eq(rows) unless @unrelated
    end
  end
end
