# frozen_string_literal: true

require 'base64'
require 'json'
require 'net/http'
require 'rexml/document'

# Uses Ruby's HTTP/XML libraries independently from Framework's HTTP client.
class WebDAVNativeClient
  CREDENTIALS = %w[lab-dav-user lab-dav-password].freeze
  CONTENT = "module-target-existing-content\n"

  attr_reader :commands

  def initialize(host, port)
    @host = host
    @port = Integer(port.to_s, 10)
    @commands = []
  end

  def request(method, path, body: nil, credentials: nil, headers: {})
    message = Net::HTTPGenericRequest.new(method, !body.nil?, true, path, headers)
    message.basic_auth(*credentials) if credentials
    message.body = body if body
    client = Net::HTTP.new(@host, @port, nil)
    client.open_timeout = 3
    client.read_timeout = 5
    client.max_retries = 0
    response = client.request(message)
    commands << {
      method: method, path: path, user: credentials&.first, status: response.code.to_i,
      headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s)
    }
    response
  end

  def qualify
    %w[dav auth readonly plain].each do |directory|
      credentials = directory == 'auth' ? CREDENTIALS : nil
      options = request('OPTIONS', "/#{directory}/", credentials: credentials)
      raise "OPTIONS #{directory}: #{options.code}" unless options.code == '200'
      raise "DAV capability differs: #{directory}" unless options['DAV'].to_s.empty? == (directory == 'plain')

      response = request('GET', "/#{directory}/existing.txt", credentials: credentials)
      raise "GET #{directory} differs" unless response.code == '200' && response.body == CONTENT
      next if directory == 'plain'

      response = request('PROPFIND', "/#{directory}/", credentials: credentials, headers: { 'Depth' => '1' })
      raise "PROPFIND #{directory}: #{response.code}" unless response.code == '207'

      hrefs = REXML::XPath.match(REXML::Document.new(response.body), '//*[local-name()="href"]').map(&:text)
      raise "Missing actual DAV content: #{directory}" unless hrefs.include?("/#{directory}/existing.txt")
    end
    raise 'Missing authentication not enforced' unless request('OPTIONS', '/auth/').code == '401'
    raise 'Wrong authentication not enforced' unless request('OPTIONS', '/auth/', credentials: ['lab-dav-user', 'wrong']).code == '401'
    raise 'Default infinite depth unexpectedly permitted' unless request('PROPFIND', '/dav/').code == '403'

    %w[dav auth].each do |directory|
      credentials = directory == 'auth' ? CREDENTIALS : nil
      path = "/#{directory}/native-proof.txt"
      2.times do
        raise 'Native file already exists' unless request('GET', path, credentials: credentials).code == '404'

        data = "module-target-native-dav [literal]\n"
        begin
          raise 'Native PUT failed' unless request('PUT', path, body: data, credentials: credentials).code == '201'

          response = request('GET', path, credentials: credentials)
          raise 'Native PUT readback differs' unless response.code == '200' && response.body == data
          raise 'Native DELETE failed' unless request('DELETE', path, credentials: credentials).code == '204'
          raise 'Native DELETE left file' unless request('GET', path, credentials: credentials).code == '404'
        ensure
          # Only the native control's own fixed path is eligible for cleanup.
          request('DELETE', path, credentials: credentials)
        end
      end
    end
    %w[readonly plain].each do |directory|
      expected = directory == 'readonly' ? '403' : '405'
      raise 'Write policy differs' unless request('PUT', "/#{directory}/native-denied.txt", body: 'native-denied').code == expected
      raise 'Denied write created file' unless request('GET', "/#{directory}/native-denied.txt").code == '404'
      raise 'Delete policy differs' unless request('DELETE', "/#{directory}/existing.txt").code == expected
      raise 'Denied delete changed file' unless request('GET', "/#{directory}/existing.txt").body == CONTENT
    end
    self
  end
end

if $PROGRAM_NAME == __FILE__
  client = WebDAVNativeClient.new(*ARGV)
  begin
    client.qualify
  ensure
    puts JSON.pretty_generate(commands: client.commands)
  end
end
