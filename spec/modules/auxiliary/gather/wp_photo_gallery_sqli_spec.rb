require 'rspec'
require 'msfenv'
require 'msf/base'
require 'cgi'
require 'metasploit/framework/hashes'

RSpec.describe 'Photo Gallery scalar extraction contracts' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('PHOTO_GALLERY_OWNER_SOURCE', File.expand_path('../../../../modules/auxiliary/gather/wp_photo_gallery_sqli.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:captures) { JSON.parse(File.read(File.expand_path('../../../file_fixtures/modules/auxiliary/gather/wp_photo_gallery_sqli/responses.json', __dir__))).fetch('responses') }
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:profile) { { 'ajax' => '/wp-admin/admin-ajax.php', 'shortcode' => '1', 'template' => 'mixed_scalar' } }
  let(:query_reply) { :modeled }
  let(:wire_mode) { :normal }
  let(:table_prefix) { 'wp_' }
  let(:group_limit) { 65_535 }
  # Synthetic inert hash-length data; no native user/hash response is committed.
  let(:hash_value) { '$wp$2y$10$' + ('a' * 53) }
  let(:rows) { %w[module_admin module_author module_reader module_editor].map { |username| [username, hash_value] } }
  let(:requests) { [] }
  let(:queries) { [] }
  let(:frames) { [] }
  let(:credentials) { [] }
  let(:loot) { [] }
  let(:reports) { [] }

  before do
    mod.datastore.merge!('RHOSTS' => '192.0.2.10', 'RHOST' => '192.0.2.10', 'RPORT' => 80, 'SSL' => false, 'AutoCheck' => false)
    allow(mod).to receive(:framework).and_return(framework)
    allow(mod).to receive(:user_output).and_return(Rex::Ui::Text::Output::Buffer.new)
    allow(mod).to receive(:myworkspace_id).and_return(1)
    allow(mod).to receive(:create_credential) { |data| credentials << data }
    allow(mod).to receive(:store_loot) do |*arguments|
      loot << arguments
      '/unit/photo-users.txt'
    end
    %i[report_host report_service report_vuln].each { |method| allow(mod).to receive(method) { |*arguments| reports << [method, arguments] } }
    %i[print_line print_status print_good print_error print_warning vprint_status vprint_good vprint_error elog].each { |method| allow(mod).to receive(method) }
    allow(mod).to receive(:rand).and_call_original
    allow(mod).to receive(:rand).with(0..19).and_return(0)
    # HTTP, UI, persistence and this bounded SQL evaluator are doubles. Actual
    # Common SQL generation/decoding, HTML parsing, WordPress prefix/reporting
    # helpers and AutoCheck execute. Native ownership/session claims do not follow.
    allow(mod).to receive(:send_request_cgi) do |options|
      requests << options
      if options['uri'] != profile['ajax']
        reply(404, 'Not Found')
      elsif options.dig('vars_get', 'shortcode_id').to_s != profile['shortcode']
        response('unknown_shortcode')
      elsif !options.fetch('vars_get').key?('bwg_tag_id_bwg_thumbnails_0[]')
        response('ordinary')
      elsif query_reply == :modeled
        scalar_response(options)
      else
        query_reply
      end
    end
  end

  def reply(code, body = '')
    Rex::Proto::Http::Response.new(code).tap { |result| result.body = body }
  end

  def response(name)
    data = captures.fetch(name)
    reply(data.fetch('code'), data.fetch('body'))
  end

  def sql_value(sql)
    queries << sql
    if (match = sql.match(/\Aselect hex\(0x([0-9a-f]+)\)\z/i))
      match[1].upcase
    elsif (match = sql.match(/\Aselect 0x([0-9a-f]+)\z/i))
      [match[1]].pack('H*')
    elsif sql.casecmp?('select NULL')
      nil
    elsif sql.match?(/\Aselect repeat\(0x[0-9a-f]+,0\)\z/i)
      ''
    elsif sql.include?('information_schema.tables') && sql.match?(/\ASELECT \d+/)
      table_prefix == 'wp_' ? sql[/\ASELECT (\d+)/, 1] : nil
    elsif sql.start_with?('SELECT LEFT(table_name')
      table_prefix
    elsif sql.match?(/\Aselect count\(1\) from \w+users\z/i)
      rows.length.to_s
    elsif (match = sql.match(/from (\w+users) limit (\d+),1\z/i))
      raise ArgumentError, 'Wrong modeled users table' unless match[1] == table_prefix + 'users'

      rows.fetch(match[2].to_i).map { |field| field.b.unpack1('H*').upcase }.join(';')
    elsif sql.include?('group_concat')
      limit = sql[/from \w+users limit (\d+)/i, 1]
      selected = limit ? rows.first(limit.to_i) : rows
      selected.map { |fields| fields.join(';') }.join(',').b.byteslice(0, group_limit)
    else
      raise ArgumentError, "Unexpected modeled SQL: #{sql}"
    end
  end

  def scalar_response(options)
    injection = options.fetch('vars_get').fetch('bwg_tag_id_bwg_thumbnails_0[]')
    expression = injection[/\A\)"(?: AND 0)? UNION SELECT (?:\d+,){7}\((.*)\)(?:,\d+){15} -- -\z/im, 1]
    raise ArgumentError, 'Unexpected unit UNION envelope' unless expression

    # This is the independently native-probed SQL transport form, not a SQL
    # engine. Marker/scalar substitution into the captured DOM is synthetic.
    match = expression.match(/\Aconcat\(0x([0-9a-f]+),ifnull\(concat\(0x56,hex\(cast\(\((.*)\) as binary\)\)\),0x4e\),0x([0-9a-f]+)\)\z/im)
    if match
      start_marker, end_marker = [match[1], match[3]].map { |hex| [hex].pack('H*') }
      value = sql_value(match[2])
      displayed = start_marker + (value.nil? ? 'N' : 'V' + value.b.unpack1('H*').upcase) + end_marker
      frames << { start: start_marker, end: end_marker, value: value }
      displayed = start_marker + 'VABC' + end_marker if wire_mode == :malformed
      displayed = displayed.sub(start_marker, 'wrong-query-marker') if wire_mode == :wrong_marker
      displayed = injection if wire_mode == :reflection
    else
      displayed = sql_value(expression).to_s
    end
    displayed = displayed.dup.force_encoding(Encoding::UTF_8)
    template = profile.fetch('template')
    template = 'framed_null' if match && value.nil? && template == 'mixed_scalar'
    template = 'framed_empty' if match && value == '' && template == 'mixed_scalar'
    capture = captures.fetch(template)
    body = capture.fetch('body').gsub(capture.fetch('placeholder'), CGI.escapeHTML(displayed))
    if wire_mode == :ambiguous && match
      different = start_marker + 'V6576696C' + end_marker
      body = body.sub('</a>', "</a><img alt=\"#{different}\" />")
    end
    reply(200, body)
  end

  def rejected(reason)
    expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
    expect(mod.fail_reason).to eq(reason)
    expect(credentials).to be_empty
    expect(loot).to be_empty
    expect(reports).to be_empty
  end

  it 'finds the actual own scalar after an ordinary captured caption' do
    expect(mod.check).to have_attributes(code: 'vulnerable', reason: a_string_matching(/SQL injection/))
    expect(credentials).to be_empty
  end

  it 'registers COUNT5 and additive SHORTCODE_ID1 integer defaults' do
    expect(mod.options.values_at('COUNT', 'SHORTCODE_ID')).to all(be_a(Msf::OptInt))
    expect(%w[COUNT SHORTCODE_ID].map { |name| mod.datastore[name] }).to eq([5, 1])
  end

  { 5 => 4, 0 => 4, 2 => 2 }.each do |count, expected|
    it "preserves exact credentials and loot with COUNT #{count}" do
      mod.datastore['COUNT'] = count
      mod.run
      expect(credentials.map { |data| [data[:username], data[:private_data]] }).to eq(rows.first(expected))
      expect(credentials).to all(include(private_type: :nonreplayable_hash, service_name: 'WordPress'))
      expect(loot.first.fetch(3)).to eq(rows.first(expected).map { |username, hash| "Username: #{username}, Password Hash: #{hash}\n" }.join)
    end
  end

  it 'suppresses ordinary SQL rows and uses only hexadecimal frame literals' do
    mod.check
    injection = requests.last.fetch('vars_get').fetch('bwg_tag_id_bwg_thumbnails_0[]')
    expect(injection).to include('AND 0')
    expect(injection).not_to include(frames.last.fetch(:start), frames.last.fetch(:end))
  end

  { '42' => 'framed_show', '43' => 'framed_title_off' }.each do |shortcode, template|
    context "with genuine shortcode #{shortcode}" do
      before do
        profile.merge!('shortcode' => shortcode, 'template' => template)
        mod.datastore['SHORTCODE_ID'] = shortcode.to_i
      end

      it('finds its own frame in the available title/alt channels') { expect(mod.check.code).to eq('vulnerable') }
      it 'collects without requiring image-title display' do
        mod.run
        expect(credentials.length).to eq(4)
      end
    end
  end

  it 'preserves framed SQL NULL as nil for custom-prefix fallback' do
    expect(mod.get_sqli_object.run_sql('select NULL')).to be_nil
  end

  it 'preserves framed empty scalar text rather than NULL' do
    expect(mod.get_sqli_object.run_sql('select repeat(0x61,0)')).to eq('')
  end

  it 'preserves leading/trailing whitespace inside framed scalar data' do
    expect(mod.get_sqli_object.run_sql('select 0x2020636166c3a9200a').b).to eq("  café \n".b)
  end

  context 'with a synthetic custom table prefix' do
    let(:table_prefix) { 'custom_' }

    it 'uses the real helper SQL NULL fallback at indicator zero' do
      mod.run
      expect(queries.any? { |sql| sql.include?('from custom_users') }).to be(true)
    end
  end

  context 'with the native no-title display setting' do
    before { profile['template'] = 'framed_title_off' }

    it('does not depend on a title div') { expect(mod.check.code).to eq('vulnerable') }
  end

  %i[reflection wrong_marker malformed ambiguous].each do |mode|
    context "with synthetic #{mode} DOM content" do
      let(:wire_mode) { mode }

      it('returns reason-bearing Unknown') { expect(mod.check).to have_attributes(code: 'unknown', reason: a_string_matching(/Photo|SQL|frame/)) }
      it('aborts a disabled-AutoCheck run without reports') { rejected(Msf::Module::Failure::UnexpectedReply) }
    end
  end

  %w[ordinary unknown_shortcode empty_gallery fixed_no_images].each do |name|
    context "with unframed native response #{name}" do
      let(:query_reply) { response(name) }

      it('does not infer safety from missing frames') { expect(mod.check.code).to eq('unknown') }
      it('aborts without credentials or loot') { rejected(Msf::Module::Failure::UnexpectedReply) }
    end
  end

  { 'nil' => nil, '401' => 401, '404' => 404, '500' => 500 }.each do |label, status|
    context "with request response #{label}" do
      let(:query_reply) { status && reply(status, 'Error') }

      it('returns Unknown') { expect(mod.check.code).to eq('unknown') }
      it 'aborts with an appropriate failure' do
        reason = status.nil? ? Msf::Module::Failure::Unreachable : Msf::Module::Failure::UnexpectedReply
        reason = Msf::Module::Failure::NoAccess if status == 401
        rejected(reason)
      end
    end
  end

  [Rex::ConnectionRefused.new, Rex::TimeoutError.new, OpenSSL::SSL::SSLError.new('Unit TLS failure')].each do |error|
    context "with expected transport error #{error.class}" do
      before { allow(mod).to receive(:send_request_cgi).and_raise(error) }

      it 'keeps both public error contracts' do
        result = nil
        expect { result = mod.check }.not_to raise_error
        expect(result.code).to eq('unknown')
        rejected(Msf::Module::Failure::Unreachable)
      end
    end
  end

  it 'rejects negative COUNT before collecting' do
    mod.datastore['COUNT'] = -1
    rejected(Msf::Module::Failure::BadConfig)
  end

  it 'preserves configured path and options over repeated runs' do
    mod.run
    profile['ajax'] = '/wordpress/wp-admin/admin-ajax.php'
    mod.datastore.merge!('TARGETURI' => '/wordpress/', 'COUNT' => 2)
    settings = mod.datastore.to_h.dup
    mod.run
    expect(credentials.length).to eq(6)
    expect(mod.datastore.to_h).to eq(settings)
  end

  it 'preserves normal AutoCheck collection' do
    mod.datastore['AutoCheck'] = true
    mod.run
    expect(credentials.length).to eq(4)
  end
end
