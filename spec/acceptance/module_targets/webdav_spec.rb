require 'acceptance_spec_helper'
require 'rbconfig'
require_relative '../../../test/module_targets/webdav/native_client'

RSpec.describe 'Native Apache WebDAV targets' do
  include_context 'module target'

  let_it_be(:native) do
    endpoint = target_endpoint('apache')
    WebDAVNativeClient.new(endpoint.fetch('host'), endpoint.fetch('port'))
  end

  before(:all) do
    expect(target_exec('apache', 'httpd', '-M')).to include('dav_module', 'dav_fs_module')
    endpoint = target_endpoint('apache')
    argv = [RbConfig.ruby, 'test/module_targets/webdav/native_client.rb', endpoint.fetch('host'), endpoint.fetch('port').to_s]
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-webdav-preflight.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-webdav-preflight-command.json'), JSON.pretty_generate(argv: argv, error: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
  end

  after do
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-webdav-http.json'), JSON.pretty_generate(native.commands))
  end

  %w[dav auth readonly].each do |directory|
    it "detects actual DAV capability on #{directory}" do
      output = run_target_module('auxiliary/scanner/http/webdav_scanner', 'apache', dav_options(directory))
      expect(output).to include('has WEBDAV ENABLED')
    end

    it "enumerates the actual existing file through #{directory}" do
      output = run_target_module('auxiliary/scanner/http/webdav_website_content', 'apache', dav_options(directory))
      expect(output).to include('Found file or directory in WebDAV response', "/#{directory}/existing.txt")
    end
  end

  it 'does not identify ordinary HTTP as DAV' do
    output = run_target_module('auxiliary/scanner/http/webdav_scanner', 'apache', dav_options('plain'))
    expect(output).to include('WebDAV disabled.')
    expect(output).not_to include('has WEBDAV ENABLED')
  end

  it 'lists only the collection itself at depth zero' do
    response = native.request('PROPFIND', '/dav/', headers: { 'Depth' => '0' })
    expect(response.code).to eq('207')
    hrefs = REXML::XPath.match(REXML::Document.new(response.body), '//*[local-name()="href"]').map(&:text)
    expect(hrefs).to eq(['/dav/'])
    output = run_target_module('auxiliary/scanner/http/webdav_website_content', 'apache', dav_options('dav').merge('DEPTH' => '0'))
    expect(output).to include('Found file or directory in WebDAV response', '/dav/')
    expect(output).not_to include('/dav/existing.txt')
  end

  it 'does not report content when the server refuses explicit infinite depth' do
    expect(native.request('PROPFIND', '/dav/', headers: { 'Depth' => 'infinity' }).code).to eq('403')
    output = run_target_module('auxiliary/scanner/http/webdav_website_content', 'apache', dav_options('dav').merge('DEPTH' => 'infinity'))
    expect(output).to include('PROPFIND returned HTTP 403')
    expect(output).not_to include('Found file or directory in WebDAV response')
  end

  it 'does not expose protected content with incorrect credentials' do
    options = dav_options('auth').merge('HttpPassword' => 'wrong')
    output = run_target_module('auxiliary/scanner/http/webdav_scanner', 'apache', options)
    expect(output).not_to include('has WEBDAV ENABLED')
    output = run_target_module('auxiliary/scanner/http/webdav_website_content', 'apache', options)
    expect(output).not_to include('Found file or directory')
  end

  %w[dav auth].each do |directory|
    it "uploads, overwrites and deletes actual text twice on #{directory}" do
      exercise_file(directory, 'module-target-module-proof.txt', 'module-target-first-text', 'module-target-second-text')
    end
  end

  it 'treats ordinary regular-expression characters as literal file content' do
    exercise_file('dav', 'module-target-literal-proof.txt', 'module-target [literal] (a+b).*', 'module-target replacement [literal]')
  end

  it 'supports a filename with no extension' do
    exercise_file('dav', 'module-target-extensionless', 'module-target-first', 'module-target-second')
  end

  it 'uploads exact multiline text through the documented file input option' do
    first = "Module target first line\nSecond line with \"quotes\" and a \\ backslash\n"
    second = "Module target replacement\nLiteral [brackets] remain text\n"
    exercise_file('dav', 'module-target-file-input.txt', first, second, file_input: true)
  end

  %w[readonly plain].each do |directory|
    it "preserves real data when #{directory} denies writes and deletion" do
      options = dav_options(directory).merge('FILENAME' => 'module-target-denied.txt', 'FILEDATA' => 'module-target-denied', 'ACTION' => 'PUT')
      output = run_target_module('auxiliary/scanner/http/http_put', 'apache', options, allow_errors: true)
      expect(output).not_to include('File uploaded:')
      expect(output).to include("File doesn't seem to exist. The upload probably failed")
      expect(native.request('GET', "/#{directory}/module-target-denied.txt").code).to eq('404')
      options.merge!('FILENAME' => 'existing.txt', 'FILEDATA' => filedata(WebDAVNativeClient::CONTENT, true), 'ACTION' => 'DELETE')
      output = run_target_module('auxiliary/scanner/http/http_put', 'apache', options, allow_errors: true)
      expect(output).not_to include('File deleted:')
      expect(output).to include('DELETE failed. File is still there.')
      expect(native.request('GET', "/#{directory}/existing.txt").body).to eq(WebDAVNativeClient::CONTENT)
    end
  end

  it 'does not upload through incorrect Basic credentials' do
    options = dav_options('auth').merge('HttpPassword' => 'wrong', 'FILENAME' => 'module-target-denied.txt', 'FILEDATA' => 'module-target-denied', 'ACTION' => 'PUT')
    output = run_target_module('auxiliary/scanner/http/http_put', 'apache', options, allow_errors: true)
    expect(output).not_to include('File uploaded:')
    expect(native.request('GET', '/auth/module-target-denied.txt', credentials: WebDAVNativeClient::CREDENTIALS).code).to eq('404')
  end

  it 'does not report a denied overwrite as a successful upload of existing matching content' do
    response = native.request('GET', '/readonly/existing.txt')
    expect(response.code).to eq('200')
    expect(response.body).to eq(WebDAVNativeClient::CONTENT)
    options = dav_options('readonly').merge('FILENAME' => 'existing.txt', 'FILEDATA' => filedata(WebDAVNativeClient::CONTENT, true), 'ACTION' => 'PUT')
    output = run_target_module('auxiliary/scanner/http/http_put', 'apache', options, allow_errors: true)
    expect(native.request('GET', '/readonly/existing.txt').body).to eq(WebDAVNativeClient::CONTENT)
    expect(output).not_to include('File uploaded:')
  end

  it 'does not treat a matching server header as proof of stored file content' do
    data = native.request('OPTIONS', '/plain/')['Server'].split.first
    response = native.request('GET', '/plain/module-target-false-positive.txt')
    expect(response.code).to eq('404')
    expect(response.body).not_to include(data)
    options = dav_options('plain').merge('FILENAME' => 'module-target-false-positive.txt', 'FILEDATA' => data, 'ACTION' => 'PUT')
    output = run_target_module('auxiliary/scanner/http/http_put', 'apache', options, allow_errors: true)
    expect(native.request('GET', '/plain/module-target-false-positive.txt').code).to eq('404')
    expect(output).not_to include('File uploaded:')
  end

  it 'does not treat an error-page body as proof of stored file content' do
    response = native.request('GET', '/plain/module-target-error-body.txt')
    expect(response.code).to eq('404')
    expect(response.body).to include('Not Found')
    options = dav_options('plain').merge('FILENAME' => 'module-target-error-body.txt', 'FILEDATA' => 'Not Found', 'ACTION' => 'PUT')
    output = run_target_module('auxiliary/scanner/http/http_put', 'apache', options, allow_errors: true)
    expect(native.request('GET', '/plain/module-target-error-body.txt').code).to eq('404')
    expect(output).not_to include('File uploaded:')
  end

  it 'does not delete an already missing file' do
    options = dav_options('dav').merge('FILENAME' => 'module-target-already-missing.txt', 'FILEDATA' => 'module-target-missing', 'ACTION' => 'DELETE')
    expect(native.request('GET', '/dav/module-target-already-missing.txt').code).to eq('404')
    output = run_target_module('auxiliary/scanner/http/http_put', 'apache', options, allow_errors: true)
    expect(output).to include('File is already gone. Will not continue DELETE')
    expect(output).not_to include('File deleted:')
  end

  def dav_options(directory)
    credentials = directory == 'auth' ? WebDAVNativeClient::CREDENTIALS : [nil, nil]
    { 'PATH' => "/#{directory}/", 'HttpUsername' => credentials.first, 'HttpPassword' => credentials.last }
  end

  def exercise_file(directory, filename, first, second, file_input: false)
    path = "/#{directory}/#{filename}"
    credentials = directory == 'auth' ? WebDAVNativeClient::CREDENTIALS : nil
    options = dav_options(directory).merge('FILENAME' => filename)
    2.times do
      expect(native.request('GET', path, credentials: credentials).code).to eq('404')
      begin
        [first, second].each do |data|
          output = run_target_module('auxiliary/scanner/http/http_put', 'apache', options.merge('ACTION' => 'PUT', 'FILEDATA' => filedata(data, file_input)), allow_errors: true)
          response = native.request('GET', path, credentials: credentials)
          expect(response.code).to eq('200')
          expect(response.body).to eq(data)
          expect(output).to include('File uploaded:')
        end
        output = run_target_module('auxiliary/scanner/http/http_put', 'apache', options.merge('ACTION' => 'DELETE', 'FILEDATA' => filedata(second, file_input)), allow_errors: true)
        expect(native.request('GET', path, credentials: credentials).code).to eq('404')
        expect(output).to include('File deleted:')
      ensure
        # Native cleanup is separate from, and cannot satisfy, the assertions.
        native.request('DELETE', path, credentials: credentials)
      end
    end
  end

  def filedata(data, from_file)
    return data unless from_file

    path = File.join(target_runtime.fetch('artifacts'), 'module-target-filedata.txt')
    File.binwrite(path, data)
    "file:#{path}"
  end
end
