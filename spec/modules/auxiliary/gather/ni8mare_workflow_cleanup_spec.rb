require 'rspec'
require 'msfenv'
require 'msf/base'
require 'base64'

RSpec.shared_context 'Ni8mare workflow HTTP setup' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('NI8MARE_CLEANUP_OWNER_SOURCE', File.expand_path('../../../../modules/auxiliary/gather/ni8mare_cve_2026_21858.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:owned_id) { 'I6o0S087V3SRTnMv' }
  let(:second_id) { 'SecondCreated002' }
  let(:foreign_id) { 'ForeignControl01' }
  let(:form_id) { '00000000-0000-4000-8000-000000000001' }
  let(:create_ids) { [owned_id, second_id] }
  let(:requests) { [] }
  let(:warnings) { [] }
  let(:errors) { [] }
  let(:loot) { [] }
  let(:create_replies) { [] }
  let(:archive_replies) { [] }
  let(:delete_replies) { [] }
  let(:login_reply) { response(200, 'data' => { 'id' => 'unit-member' }) }
  let(:start_reply) { response(200, 'data' => { 'waitingForWebhook' => true }) }
  let(:upload_reply) { response(200, 'status' => 'success') }
  let(:list_reply) { response(200, 'data' => { 'results' => [{ 'id' => '407' }] }) }
  let(:binary_content) { "\x00\xff\x80cleanup\n".b }
  let(:content_reply) do
    # Preserve the genuine 33-entry form result; replace only its data/size
    # literals with this lifecycle example's expected bytes (see fixture README).
    fixture = File.expand_path('../../../file_fixtures/modules/auxiliary/ni8mare_execution_data/native-1.120.0-json.flatted.json', __dir__)
    data = JSON.parse(File.binread(fixture))
    data[30] = Base64.strict_encode64(binary_content)
    data[32] = "#{binary_content.bytesize} B"
    response(200, 'data' => { 'data' => JSON.generate(data) })
  end
  let(:foreign_records) do
    {
      foreign_id => { 'id' => foreign_id, 'name' => 'Operator workflow', 'nodes' => [{ 'id' => 'foreign-node', 'parameters' => { 'sentinel' => 'preserve' } }] },
      'ForeignControl02' => { 'id' => 'ForeignControl02', 'name' => 'Other project', 'nodes' => [] }
    }
  end
  let(:registry) { Marshal.load(Marshal.dump(foreign_records)) }

  def response(code, document)
    Rex::Proto::Http::Response.new(code).tap { |res| res.body = JSON.generate(document) }
  end

  def cleanup_requests
    requests.select { |request| request['method'] == 'DELETE' || request['uri'].end_with?('/archive') }
  end

  def set_cookie(value)
    mod.cookie_jar.clear
    mod.cookie_jar.parse_and_merge("n8n-auth=#{value}; Path=/", 'http://192.0.2.10:5678/')
  end

  before do
    mod.datastore.merge!(
      'RHOSTS' => '192.0.2.10', 'RPORT' => 5678,
      'USERNAME' => 'member@example.test', 'PASSWORD' => 'controlled-member-password',
      'ACTION' => 'READ_FILE', 'TARGET_FILENAME' => '/tmp/cleanup-proof.bin'
    )
    set_cookie('original-unit-cookie')
    allow(SecureRandom).to receive(:uuid).and_return(form_id)
    allow(mod).to receive(:print_warning) { |message| warnings << message }
    allow(mod).to receive(:elog) { |message, **details| errors << [message, details] }
    allow(mod).to receive(:store_loot) do |*arguments|
      loot << arguments
      '/unit/cleanup-proof.bin'
    end
    # Only HTTP and loot storage are doubles. Ownership, creation/start/upload,
    # extraction parsing, cookie jars, archive/delete, reset and cleanup are real.
    # The create/start/archive/delete shapes follow genuine n8n captures.
    allow(mod).to receive(:send_request_cgi) do |request|
      requests << request
      method = request.fetch('method')
      uri = request.fetch('uri')
      if method == 'POST' && uri == '/rest/login'
        login_reply
      elsif method == 'POST' && uri == '/rest/workflows'
        if create_replies.empty?
          id = create_ids.shift
          submitted = JSON.parse(request.fetch('data'))
          registry[id] = submitted.merge('id' => id)
          response(200, 'data' => { 'id' => id, 'nodes' => submitted.fetch('nodes'), 'versionId' => form_id })
        else
          reply = create_replies.shift
          document = reply&.get_json_document
          id = document.is_a?(Hash) && document['data'].is_a?(Hash) ? document['data']['id'] : nil
          id ||= document['id'] if document.is_a?(Hash)
          registry[id] = { 'id' => id, 'name' => 'Partial created workflow' } if id.is_a?(String) && !id.empty?
          reply
        end
      elsif method == 'POST' && uri.end_with?('/run')
        start_reply
      elsif method == 'POST' && uri == "/form-test/#{form_id}"
        upload_reply
      elsif method == 'GET' && uri == '/rest/executions'
        list_reply
      elsif method == 'GET' && uri == '/rest/executions/407'
        content_reply
      elsif method == 'POST' && uri.end_with?('/archive')
        id = uri.split('/')[-2]
        reply = archive_replies.empty? ? response(200, 'data' => { 'id' => id }) : archive_replies.shift
        raise reply if reply.is_a?(Exception)

        reply
      elsif method == 'DELETE' && uri.start_with?('/rest/workflows/')
        id = uri.split('/').last
        reply = delete_replies.empty? ? response(200, 'data' => true) : delete_replies.shift
        raise reply if reply.is_a?(Exception)

        document = reply&.get_json_document
        registry.delete(id) if reply&.code == 200 && document.is_a?(Hash) && document['data'] == true
        reply
      else
        raise ArgumentError, "Unexpected unit HTTP request: #{request}"
      end
    end
  end

  after do |example|
    if (path = ENV['NI8MARE_CLEANUP_UNIT_EVIDENCE'])
      serializable_requests = requests.map do |request|
        request.transform_values do |value|
          value.is_a?(Msf::Exploit::Remote::HTTP::HttpCookieJar) ? value.cookies.map(&:to_s) : value
        end
      end
      File.open(path, 'a') do |file|
        file.puts(JSON.generate(example: example.full_description, requests: serializable_requests, warnings: warnings, errors: errors.map(&:first), remaining_ids: registry.keys, fail_reason: mod.fail_reason))
      end
    end
  end
end

RSpec.describe 'Ni8mare owned workflow cleanup' do
  include_context 'Ni8mare workflow HTTP setup'

  it 'retains exact loot and deletes only the newly created workflow on success' do
    mod.run
    mod.cleanup

    expect(loot.first[3]).to eq(binary_content)
    expect(cleanup_requests.map { |request| [request['method'], request['uri']] }).to eq([
      ['POST', "/rest/workflows/#{owned_id}/archive"], ['DELETE', "/rest/workflows/#{owned_id}"]
    ])
    expect(registry).to eq(foreign_records)
  end

  context 'when the public form guard rejects the upload' do
    let(:upload_reply) { response(500, 'message' => 'Expected multipart/form-data') }

    it 'preserves the real primary failure and removes the known created workflow' do
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, 'unexpected-reply: Received unexpected response')
      mod.cleanup

      expect(mod.fail_reason).to eq(Msf::Module::Failure::UnexpectedReply)
      expect(registry).to eq(foreign_records)
      expect(cleanup_requests.map { |request| request['method'] }).to eq(%w[POST DELETE])
      expect(loot).to be_empty
    end

    it 'retains the original failure if archive fails and retries the exact owned ID' do
      archive_replies.push(response(500, 'message' => 'Archive rejected'))
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, 'unexpected-reply: Received unexpected response')
      expect(warnings).to include("Could not archive workflow #{owned_id}; archive and delete it manually.")
      expect(registry).to have_key(owned_id)
      mod.cleanup

      expect(mod.fail_reason).to eq(Msf::Module::Failure::UnexpectedReply)
      expect(cleanup_requests.map { |request| request['uri'] }).to eq([
        "/rest/workflows/#{owned_id}/archive", "/rest/workflows/#{owned_id}/archive", "/rest/workflows/#{owned_id}"
      ])
      expect(registry).to eq(foreign_records)
    end

    it 'reports an archive connection error without masking the original rejection' do
      archive_replies.push(Rex::ConnectionError.new('Controlled cleanup connection failure'))
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, 'unexpected-reply: Received unexpected response')

      expect(errors.first.first).to eq("Failed to clean up n8n workflow #{owned_id}")
      expect(errors.first.last[:error]).to be_a(Rex::ConnectionError)
      expect(warnings).to include("Could not clean up workflow #{owned_id}; archive and delete it manually.")
      expect(mod.fail_reason).to eq(Msf::Module::Failure::UnexpectedReply)
    end
  end

  context 'when starting the created workflow fails' do
    let(:start_reply) { response(500, 'message' => 'Controlled start failure') }

    it 'cleans up partial success without replacing the start failure' do
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, 'unexpected-reply: Workflow may not run, received unexpected reply')

      expect(registry).to eq(foreign_records)
      expect(cleanup_requests.last).to include('method' => 'DELETE', 'uri' => "/rest/workflows/#{owned_id}")
    end
  end

  context 'when the create reply contains a known ID but lacks activation metadata' do
    let(:create_replies) { [response(200, 'data' => { 'id' => owned_id })] }

    it 'owns and removes the exact created ID before reporting missing metadata' do
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, 'not-found: Failed to get workflow ID from response')

      expect(registry).to eq(foreign_records)
      expect(cleanup_requests.map { |request| request['method'] }).to eq(%w[POST DELETE])
    end
  end

  context 'when the create reply contains only a top-level known ID' do
    let(:create_replies) { [response(201, 'id' => owned_id)] }

    it 'still removes the known created workflow after rejecting incomplete metadata' do
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, 'not-found: Failed to get workflow ID from response')

      expect(registry).to eq(foreign_records)
      expect(cleanup_requests.last).to include('uri' => "/rest/workflows/#{owned_id}")
    end
  end

  context 'when workflow creation does not respond' do
    let(:create_replies) { [nil] }

    it 'reports the missing create reply without reusing a stale foreign ID' do
      mod.instance_variable_set(:@workflow_id, foreign_id)
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, 'unexpected-reply: Failed to create workflow: ')
      mod.cleanup

      expect(cleanup_requests).to be_empty
      expect(registry).to eq(foreign_records)
    end
  end

  context 'when workflow creation returns malformed data' do
    let(:create_replies) { [response(200, 'data' => [])] }

    it 'does not dereference malformed metadata or claim ownership of a stale ID' do
      mod.instance_variable_set(:@workflow_id, foreign_id)
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, 'not-found: Failed to get workflow ID from response')
      mod.cleanup

      expect(cleanup_requests).to be_empty
      expect(registry).to eq(foreign_records)
    end
  end

  context 'when workflow creation is denied' do
    let(:create_replies) { [response(403, 'message' => 'Denied')] }

    it 'preserves foreign records and sends no archive or delete request' do
      mod.instance_variable_set(:@workflow_id, foreign_id)
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, 'unexpected-reply: Failed to create workflow: 403')
      mod.cleanup

      expect(cleanup_requests).to be_empty
      expect(registry).to eq(foreign_records)
    end
  end

  context 'when execution listing fails' do
    let(:list_reply) { response(500, 'message' => 'Controlled listing failure') }

    it 'cleans up while preserving the listing failure' do
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, 'unexpected-reply: Received unexpected reply, could not get run ID')

      expect(registry).to eq(foreign_records)
    end
  end

  context 'when extracted file content is missing' do
    let(:content_reply) { response(200, 'data' => {}) }

    it 'cleans up while preserving the extraction failure' do
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, 'payload-failed: Failed to read the file')

      expect(registry).to eq(foreign_records)
      expect(loot).to be_empty
    end
  end

  context 'when upload raises a transport timeout' do
    let(:upload_reply) { raise Rex::TimeoutError, 'Controlled upload timeout' }

    it 'cleans up without replacing the original expected transport error' do
      expect { mod.run }.to raise_error(Rex::TimeoutError, 'Controlled upload timeout')

      expect(registry).to eq(foreign_records)
    end
  end

  it 'retains useful loot and retries only deletion after an archive already succeeded' do
    delete_replies.push(response(500, 'message' => 'Delete rejected'))
    mod.run
    expect(loot.first[3]).to eq(binary_content)
    expect(warnings).to include("Could not delete workflow #{owned_id}; delete it manually.")
    mod.cleanup
    mod.cleanup

    expect(cleanup_requests.map { |request| request['method'] }).to eq(%w[POST DELETE DELETE])
    expect(registry).to eq(foreign_records)
  end

  it 'does not lose successful extraction when deletion raises an expected timeout' do
    delete_replies.push(Rex::TimeoutError.new('Controlled delete timeout'))
    expect { mod.run }.not_to raise_error

    expect(loot.first[3]).to eq(binary_content)
    expect(errors.first.last[:error]).to be_a(Rex::TimeoutError)
    expect(warnings).to include("Could not clean up workflow #{owned_id}; archive and delete it manually.")
  end

  it 'does not accept a malformed archive response as confirmed cleanup' do
    archive_replies.push(response(200, 'data' => []))
    expect { mod.run }.not_to raise_error

    expect(cleanup_requests.map { |request| request['method'] }).to eq(['POST'])
    expect(registry).to have_key(owned_id)
    expect(warnings).to include("Could not archive workflow #{owned_id}; archive and delete it manually.")
  end

  it 'keeps an uncertain deletion for retry rather than falsely retiring it' do
    delete_replies.push(nil)
    mod.run
    mod.cleanup

    expect(cleanup_requests.map { |request| request['method'] }).to eq(%w[POST DELETE DELETE])
    expect(registry).to eq(foreign_records)
  end

  it 'chains parent cleanup even when its owned workflow archive fails' do
    mod.create_file_upload_workflow
    archive_replies.push(Rex::ConnectionError.new('Controlled archive failure'))
    expect(mod).to receive(:abort_sockets)
    expect { mod.cleanup }.not_to raise_error

    expect(cleanup_requests.last).to include('method' => 'POST', 'uri' => "/rest/workflows/#{owned_id}/archive")
  end

  it 'uses captured ownership and cookies instead of mutable current workflow and account state' do
    mod.create_file_upload_workflow
    mod.instance_variable_set(:@workflow_id, foreign_id)
    set_cookie('later-unit-cookie')
    mod.cleanup

    expect(cleanup_requests.map { |request| request['uri'] }).to eq(["/rest/workflows/#{owned_id}/archive", "/rest/workflows/#{owned_id}"])
    expect(cleanup_requests.map { |request| request.fetch('cookie').cookies.map(&:to_s) }).to eq([['n8n-auth=original-unit-cookie']] * 2)
    expect(registry).to eq(foreign_records)
  end

  it 'passes the captured cookie jar through the real HttpClient explicit-cookie API' do
    mod.create_file_upload_workflow
    set_cookie('later-unit-cookie')
    mod.cleanup
    archive_request = cleanup_requests.first
    expect(archive_request).to be_a(Hash)
    expect(mod).to receive(:send_request_raw).with(
      hash_including('cookie' => 'n8n-auth=original-unit-cookie', 'cgi' => true), 20, true
    ).and_return(response(200, 'data' => { 'id' => owned_id }))

    # Only the actual transport is doubled here. HttpClient filters and converts
    # the real cloned jar into its wire header instead of using the current jar.
    Msf::Exploit::Remote::HttpClient.instance_method(:send_request_cgi).bind(mod).call(archive_request)
  end

  it 'defers cleanup after an origin change and retries only the original owned target' do
    mod.create_file_upload_workflow
    mod.datastore['RHOSTS'] = '192.0.2.11'
    mod.cleanup
    expect(cleanup_requests).to be_empty
    expect(warnings).to include("Skipping cleanup of workflow #{owned_id} because the n8n target has changed; archive and delete it manually.")

    mod.datastore['RHOSTS'] = '192.0.2.10'
    mod.cleanup
    expect(registry).to eq(foreign_records)
  end

  it 'does not repeat cleanup after confirmed removal and clears the current workflow ID' do
    mod.run
    mod.cleanup
    mod.cleanup

    expect(cleanup_requests.length).to eq(2)
    expect(mod.instance_variable_get(:@workflow_id)).to be_nil
  end

  it 'resets failed cleanup state before a later run with bad credentials' do
    archive_replies.push(response(500, 'message' => 'Archive rejected'))
    mod.run
    requests.clear
    allow(mod).to receive(:send_request_cgi).with(hash_including('uri' => '/rest/login')) do |request|
      requests << request
      response(401, 'message' => 'Invalid credentials')
    end
    expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, 'no-access: Failed to login')
    mod.cleanup

    expect(requests.map { |request| request['uri'] }).to eq(['/rest/login'])
    expect(cleanup_requests).to be_empty
    expect(registry).to have_key(owned_id)
  end

  it 'does not reuse a prior owned ID when a later create reply is malformed' do
    archive_replies.push(response(500, 'message' => 'Archive rejected'))
    mod.run
    create_replies.push(response(200, {}))
    requests.clear
    expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, 'not-found: Failed to get workflow ID from response')
    mod.cleanup

    expect(cleanup_requests).to be_empty
    expect(registry).to have_key(owned_id)
    expect(registry.slice(*foreign_records.keys)).to eq(foreign_records)
  end

  it 'does not use a previous workflow on a later refused login connection' do
    archive_replies.push(response(500, 'message' => 'Archive rejected'))
    mod.run
    requests.clear
    refused = Rex::ConnectionError.new
    allow(mod).to receive(:send_request_cgi).with(hash_including('uri' => '/rest/login')) do |request|
      requests << request
      raise refused
    end
    expect { mod.run }.to raise_error(Rex::ConnectionError) { |error| expect(error).to equal(refused) }
    mod.cleanup

    expect(cleanup_requests).to be_empty
    expect(registry.slice(*foreign_records.keys)).to eq(foreign_records)
  end

  it 'cleans up independent owned workflows across successful repeated runs' do
    mod.run
    mod.run
    mod.cleanup

    expect(cleanup_requests.map { |request| request['uri'] }).to eq([
      "/rest/workflows/#{owned_id}/archive", "/rest/workflows/#{owned_id}",
      "/rest/workflows/#{second_id}/archive", "/rest/workflows/#{second_id}"
    ])
    expect(registry).to eq(foreign_records)
  end
end
