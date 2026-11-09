# frozen_string_literal: true

require 'json'
require 'socket'

host, port = ARGV
raise ArgumentError, 'Use the owned loopback-published Apache fixture' unless host == '127.0.0.1'

captures = [['missing_host_nondefault_port', ":#{port}", true], ['default_depth', "#{host}:#{port}", false], ['depth_one', "#{host}:#{port}", true]].map do |name, authority, depth|
  request = "PROPFIND /dav/ HTTP/1.0\r\nHost: #{authority}\r\nConnection: close\r\nContent-Type: text/xml\r\nContent-Length: 0\r\n"
  request << "Depth: 1\r\n" if depth
  request << "\r\n"
  response = +''
  Socket.tcp(host, Integer(port, 10), connect_timeout: 3) do |socket|
    socket.write(request)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 3
    loop do
      remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      raise 'Native HTTP response timed out' unless remaining.positive? && IO.select([socket], nil, nil, remaining)

      begin
        response << socket.readpartial(4096)
      rescue EOFError
        break
      end
    end
  end
  head, body = response.split("\r\n\r\n", 2)
  raise 'Unexpected chunked response' if head.downcase.include?('transfer-encoding: chunked')

  { name: name, request: request, response_headers: head, status: head.lines.first.split[1].to_i, body: body }
end
puts JSON.pretty_generate(server: 'Apache HTTP Server 2.4.62', captures: captures)
