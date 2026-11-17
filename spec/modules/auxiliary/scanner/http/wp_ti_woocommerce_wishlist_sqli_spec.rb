require 'rspec'
require 'msfenv'
require 'msf/base'
require 'json'

RSpec.describe 'TI WooCommerce Wishlist share key discovery' do
  subject(:share_key) { mod.get_share_key }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('TI_WISHLIST_OWNER_SOURCE', File.expand_path('../../../../../modules/auxiliary/scanner/http/wp_ti_woocommerce_wishlist_sqli.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:mod) { owner_class.new }
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:capture) do
    JSON.parse(File.read(File.join(__dir__, '../../../../file_fixtures/modules/auxiliary/scanner/http/wp_ti_woocommerce_wishlist_sqli/share_key_responses.json')))
  end
  let(:valid_document) { JSON.parse(capture.fetch('responses').fetch('successful_add').fetch('body')) }
  let(:expected_key) { valid_document.fetch('wishlist').fetch('share_key') }
  let(:responses) { [captured_response('successful_add')] }
  let(:requests) { [] }

  before do
    mod.datastore.merge!('RHOSTS' => '192.0.2.10', 'RHOST' => '192.0.2.10', 'RPORT' => 8080, 'VHOST' => 'module-target.test', 'SSL' => false, 'TARGETURI' => '/', 'PRODUCT_ID_MIN' => 11, 'PRODUCT_ID_MAX' => 11)
    allow(mod).to receive(:framework).and_return(framework)
    %i[print_status print_good print_error print_warning vprint_status].each { |method| allow(mod).to receive(method) }
    allow(mod).to receive(:send_request_cgi) do |options, *_arguments|
      requests << options.deep_dup
      responses.shift
    end
  end

  # The real discovery method, multipart encoder and Rex JSON parser run over
  # HTTP/Framework/UI doubles. The fixture contains complete native JSON and a
  # verbatim absent-plugin HTML prefix; malformed variants below are synthetic.
  # No WordPress installation, SQL injection or credential reporting runs here.

  it 'returns the key from captured JSON with products keyed by product ID' do
    expect(share_key).to eq(expected_key)
  end

  it 'keeps accepting a nonempty product array' do
    valid_document['wishlists_data']['products'] = [valid_document['wishlists_data']['products'].values.first]
    responses.replace([json_response(valid_document)])

    expect(share_key).to eq(expected_key)
  end

  it 'reports the existing not-found failure for the captured empty-product response' do
    responses.replace([captured_response('invalid_product')])

    expect { share_key }.to raise_error(Msf::Auxiliary::Failed, /not-found: No valid product ID found\./)
  end

  it 'reports the existing not-found failure for captured absent-plugin HTML' do
    responses.replace([captured_response('absent_html_prefix')])

    expect { share_key }.to raise_error(Msf::Auxiliary::Failed, /not-found: No valid product ID found\./)
  end

  {
    'a JSON array' => [],
    'JSON null' => nil,
    'a JSON string' => 'unrelated',
    'a JSON number' => 7,
    'a JSON boolean' => false,
    'an empty JSON object' => {},
    'a null wishlist-data value' => { 'wishlists_data' => nil },
    'an array wishlist-data value' => { 'wishlists_data' => [] },
    'a string wishlist-data value' => { 'wishlists_data' => 'unrelated' },
    'a missing products value' => { 'wishlists_data' => {} },
    'a numeric products value' => { 'wishlists_data' => { 'products' => 7 } },
    'a string products value' => { 'wishlists_data' => { 'products' => 'unrelated' }, 'wishlist' => { 'share_key' => 'synthetic-key' } },
    'a missing wishlist object' => { 'wishlists_data' => { 'products' => [11] } },
    'an array wishlist object' => { 'wishlists_data' => { 'products' => [11] }, 'wishlist' => [] },
    'a missing share key' => { 'wishlists_data' => { 'products' => [11] }, 'wishlist' => {} },
    'a numeric share key' => { 'wishlists_data' => { 'products' => [11] }, 'wishlist' => { 'share_key' => 7 } },
    'an empty share key' => { 'wishlists_data' => { 'products' => [11] }, 'wishlist' => { 'share_key' => '' } },
    'a whitespace share key' => { 'wishlists_data' => { 'products' => [11] }, 'wishlist' => { 'share_key' => " \t\n" } }
  }.each do |description, document|
    context "when the response contains #{description}" do
      let(:responses) { [json_response(document)] }

      it 'reports a reasoned not-found failure without a parser exception' do
        expect { share_key }.to raise_error(Msf::Auxiliary::Failed, /not-found: No valid product ID found\./)
      end
    end
  end

  it 'reports the existing not-found failure for malformed JSON' do
    responses.replace([http_response('{broken')])

    expect { share_key }.to raise_error(Msf::Auxiliary::Failed, /not-found: No valid product ID found\./)
  end

  it 'keeps ignoring a missing HTTP response' do
    responses.replace([nil])

    expect { share_key }.to raise_error(Msf::Auxiliary::Failed, /not-found: No valid product ID found\./)
  end

  it 'keeps ignoring a non-200 response even with valid JSON' do
    responses.first.code = 500

    expect { share_key }.to raise_error(Msf::Auxiliary::Failed, /not-found: No valid product ID found\./)
  end

  it 'continues after unrelated HTML to the next configured product ID' do
    mod.datastore['PRODUCT_ID_MAX'] = 12
    responses.replace([captured_response('absent_html_prefix'), captured_response('successful_add')])

    expect(share_key).to eq(expected_key)
    expect(requests.map { |request| request.fetch('data')[/name="product_id"\r\n\r\n(\d+)\r\n/, 1] }).to eq(%w[11 12])
  end

  it 'stops requesting products once a valid key is found' do
    mod.datastore['PRODUCT_ID_MAX'] = 13

    share_key

    expect(requests.length).to eq(1)
  end

  it 'preserves the multipart request and configured subdirectory' do
    mod.datastore['TARGETURI'] = '/wordpress/'

    share_key

    request = requests.fetch(0)
    boundary = request.fetch('ctype').delete_prefix('multipart/form-data; boundary=')
    expect(request.values_at('method', 'uri')).to eq(['POST', '/wordpress/'])
    expect(request.fetch('data')).to include("--#{boundary}\r\n", 'name="tinv_wishlist_id"', "name=\"product_id\"\r\n\r\n11\r\n", "name=\"product_action\"\r\n\r\naddto\r\n")
  end

  it 'refuses to start SQL injection when discovery only returns unrelated HTML' do
    responses.replace([captured_response('absent_html_prefix')])
    expect(mod).not_to receive(:create_sqli)

    expect { mod.run_host('192.0.2.10') }.to raise_error(Msf::Auxiliary::Failed, /not-found:/)
  end

  def captured_response(name)
    data = capture.fetch('responses').fetch(name)
    http_response(data.fetch('body'), code: data.fetch('code'))
  end

  def json_response(document)
    http_response(JSON.generate(document))
  end

  def http_response(body, code: 200)
    Rex::Proto::Http::Response.new(code).tap { |response| response.body = body }
  end
end
