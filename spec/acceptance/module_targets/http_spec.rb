require 'acceptance_spec_helper'
require 'net/http'

RSpec.describe 'HTTP module targets' do
  include_context 'module target'

  before do
    response = http_request('/')
    expect(response.code).to eq('200')
    expect(response.body).to include('module-target-http-marker')
    expect(response['Server']).to include('Apache/2.4.62')
  end

  it 'fingerprints the actual Apache version' do
    output = run_target_module('auxiliary/scanner/http/http_version', 'apache')
    expect(output).to include('Apache/2.4.62')
  end

  it 'extracts and decodes an HTML title' do
    output = run_target_module('auxiliary/scanner/http/title', 'apache')
    expect(output).to include('[C:200]', 'Module target & Apache')
  end

  it 'follows a redirect when requested' do
    expect(http_request('/redirect').code).to eq('302')
    output = run_target_module('auxiliary/scanner/http/title', 'apache', { 'TARGETURI' => '/redirect', 'FollowRedirect' => true })
    expect(output).to include('[C:200]', 'Redirect destination')
  end

  it 'does not invent a title for plain text' do
    expect(http_request('/plain.txt').body).to include('module-target-plain-marker')
    output = run_target_module('auxiliary/scanner/http/title', 'apache', { 'TARGETURI' => '/plain.txt' }, allow_errors: true)
    expect(output).to include('No webpage title')
    expect(output).not_to include('[C:200]')
  end

  it 'retrieves robots exclusions' do
    expect(http_request('/robots.txt').body).to include('Disallow: /private-area/')
    output = run_target_module('auxiliary/scanner/http/robots_txt', 'apache')
    expect(output).to include('Contents of Robots.txt:', 'Disallow: /private-area/', 'Allow: /public-area/')
  end

  it 'does not report a missing robots file' do
    expect(http_request('/missing/robots.txt').code).to eq('404')
    output = run_target_module('auxiliary/scanner/http/robots_txt', 'apache', { 'PATH' => '/missing/' })
    expect(output).not_to include('Contents of Robots.txt:', 'robots.txt found')
  end

  it 'reports the allowed HTTP methods including TRACE' do
    expect(http_request('/', method: 'OPTIONS')['Allow']).to include('TRACE')
    output = run_target_module('auxiliary/scanner/http/options', 'apache')
    expect(output).to include('allows', 'GET', 'HEAD', 'OPTIONS', 'TRACE method allowed.')
  end

  it 'identifies an actual directory listing' do
    expect(http_request('/listing/').body).to include('Index of /listing', 'evidence.txt')
    output = run_target_module('auxiliary/scanner/http/dir_listing', 'apache', { 'PATH' => '/listing/' })
    expect(output).to include('Found Directory Listing')
  end

  it 'does not report a normal index page as a directory listing' do
    output = run_target_module('auxiliary/scanner/http/dir_listing', 'apache')
    expect(output).not_to include('Found Directory Listing')
  end

  %w[HEAD GET].each do |method|
    it "retrieves headers using #{method}" do
      output = run_target_module('auxiliary/scanner/http/http_header', 'apache', { 'HTTP_METHOD' => method })
      expect(output).to include('SERVER: Apache/2.4.62', 'CONTENT-TYPE: text/html')
    end
  end

  it 'detects an enabled TRACE method from the reflected request' do
    response = http_request('/module-target-trace', method: 'TRACE')
    expect(response.body).to include('TRACE /module-target-trace HTTP/1.1')
    output = run_target_module('auxiliary/scanner/http/trace', 'apache')
    expect(output).to include('is vulnerable to Cross-Site Tracing')
  end

  it 'authenticates one valid Basic credential' do
    expect(http_request('/protected/').code).to eq('401')
    expect(http_request('/protected/', password: 'module-test-password').body).to include('module-target-protected-marker')
    output = run_target_module('auxiliary/scanner/http/http_login', 'apache', login_options('module-test-password'))
    expect(output).to include("Success: 'module-test-user:module-test-password'")
  end

  it 'rejects one incorrect Basic credential' do
    expect(http_request('/protected/', password: 'wrong-password').code).to eq('401')
    output = run_target_module('auxiliary/scanner/http/http_login', 'apache', login_options('wrong-password'), allow_errors: true)
    expect(output).to include("Failed: 'module-test-user:wrong-password'")
    expect(output).not_to include('Success:')
  end

  def login_options(password)
    {
      'AUTH_URI' => '/protected/', 'HttpUsername' => 'module-test-user', 'HttpPassword' => password,
      'USER_FILE' => '', 'PASS_FILE' => '', 'USERPASS_FILE' => '', 'BLANK_PASSWORDS' => false,
      'USER_AS_PASS' => false, 'STOP_ON_SUCCESS' => true
    }
  end

  def http_request(path, method: 'GET', password: nil)
    endpoint = target_endpoint('apache')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 3
    http.read_timeout = 3
    request = Net::HTTPGenericRequest.new(method, false, method != 'HEAD', path)
    request.basic_auth('module-test-user', password) if password
    http.request(request)
  end
end
