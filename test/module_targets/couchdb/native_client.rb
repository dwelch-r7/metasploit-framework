# frozen_string_literal: true

require 'json'
require 'net/http'

# Independent native REST controls shared by real CouchDB fixture versions.
class CouchDBNativeClient
  DEFAULT_CREDENTIALS = %w[labadmin labpassword].freeze

  attr_reader :commands

  def initialize(host, port, credentials: DEFAULT_CREDENTIALS)
    @host = host
    @port = Integer(port.to_s, 10)
    @credentials = credentials
    @commands = []
  end

  def request(method, path, data = nil, credentials = @credentials)
    client = Net::HTTP.new(@host, @port, nil)
    client.open_timeout = 3
    client.read_timeout = 5
    message = Net::HTTP.const_get(method.capitalize).new(path)
    message.basic_auth(*credentials) if credentials
    if data
      message['Content-Type'] = 'application/json'
      message.body = data.is_a?(String) ? data : JSON.generate(data)
    end
    response = client.request(message)
    body = JSON.parse(response.body)
    commands << { method: method, path: path, user: credentials&.first, request_body: message.body, status: response.code.to_i, body: body }
    [response.code.to_i, body]
  end
end
