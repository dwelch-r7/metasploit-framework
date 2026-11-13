# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/stopwatch'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # OPC-UA Connection Protocol message header is 8 bytes:
  #   MessageType (3 bytes ASCII) + Reserved (1 byte) + MessageSize (UInt32 LE)
  HEADER_LEN = 8
  BUFFER_SIZE = 65_535
  RECEIVE_TIMEOUT = 5
  MAX_REASON_LEN = 4096

  # OPC-UA StatusCodes that may appear in an ERR response from the UA TCP
  # transport. Values per the OPC Foundation StatusCodes definitions
  # (Opc.Ua.StatusCodes) and OPC-UA Specification Part 6.
  STATUS_CODES = {
    # UA TCP transport-specific errors (Part 6, 7.1.2)
    0x807D0000 => 'Bad_TcpServerTooBusy',
    0x807E0000 => 'Bad_TcpMessageTypeInvalid',
    0x807F0000 => 'Bad_TcpSecureChannelUnknown',
    0x80800000 => 'Bad_TcpMessageTooLarge',
    0x80810000 => 'Bad_TcpNotEnoughResources',
    0x80820000 => 'Bad_TcpInternalError',
    0x80830000 => 'Bad_TcpEndpointUrlInvalid',
    # Connection/security errors also seen at the transport layer
    0x80BE0000 => 'Bad_ProtocolVersionUnsupported',
    0x80130000 => 'Bad_SecurityChecksFailed',
    0x80120000 => 'Bad_CertificateInvalid',
    0x80840000 => 'Bad_RequestInterrupted',
    0x80850000 => 'Bad_RequestTimeout',
    0x80860000 => 'Bad_SecureChannelClosed',
    0x80870000 => 'Bad_SecureChannelTokenUnknown',
    0x80AC0000 => 'Bad_ConnectionRejected',
    0x80AE0000 => 'Bad_ConnectionClosed'
  }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'OPC-UA Server Detection',
        'Description' => %q{
          This module detects OPC-UA servers speaking the OPC-UA TCP binary
          transport (opc.tcp://) by sending a Hello (HEL) message and inspecting
          the response. A server that replies with an Acknowledge (ACK) message
          accepted the connection. A server that replies with an Error (ERR)
          message is still a confirmed OPC-UA server; the returned StatusCode and
          reason are reported. OPC-UA is widely deployed in industrial control
          systems, including as the standard server interface on Inductive
          Automation Ignition gateways.
        },
        'Author' => [
          'Ethan Thomason <ethan@ethomason.com>'
        ],
        'References' => [
          ['URL', 'https://reference.opcfoundation.org/Core/Part6/'],
          ['URL', 'https://opcfoundation.org/about/opc-technologies/opc-ua/']
        ],
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'RPORT' => 4840
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
  end

  # Build an OPC-UA Hello (HEL) message for the given endpoint URL.
  # Body layout (all UInt32 little-endian, then a UA String for the URL):
  #   ProtocolVersion + ReceiveBufferSize + SendBufferSize +
  #   MaxMessageSize + MaxChunkCount + EndpointUrlLength + EndpointUrl
  def build_hello(endpoint_url)
    body = [
      0,           # ProtocolVersion
      BUFFER_SIZE, # ReceiveBufferSize
      BUFFER_SIZE, # SendBufferSize
      0,           # MaxMessageSize (0 = no limit)
      0            # MaxChunkCount  (0 = no limit)
    ].pack('V*')
    body << [endpoint_url.length].pack('V') << endpoint_url

    msg_size = HEADER_LEN + body.length
    'HELF' + [msg_size].pack('V') + body
  end

  # Decode an ERR message body: UInt32 StatusCode + UA String reason.
  # Returns [status_string, reason_string].
  def decode_error(body)
    return ['unknown', ''] if body.bytesize < 4

    code = body.byteslice(0, 4).unpack1('V')
    status = STATUS_CODES[code] || format('0x%08X', code)

    reason = ''
    if body.bytesize >= 8
      reason_len = body.byteslice(4, 4).unpack1('l<')
      # Null is -1; Part 6 requires clients to ignore reasons over 4096 bytes.
      if reason_len.positive? && reason_len <= MAX_REASON_LEN && body.bytesize >= 8 + reason_len
        reason = body.byteslice(8, reason_len)
      end
    end

    [status, reason]
  end

  def run_host(ip)
    begin
      connect
      endpoint_url = "opc.tcp://#{Rex::Socket.to_authority(ip, rport)}"
      sock.put(build_hello(endpoint_url))
      data = read_response
    rescue Rex::ConnectionError, Rex::TimeoutError, ::Timeout::Error, ::IOError, Errno::ECONNRESET => e
      vprint_error("OPC-UA HEL exchange failed: #{e.message}")
      elog('OPC-UA HEL exchange failed', error: e)
      return
    end

    unless data
      vprint_status('No complete OPC-UA response to HEL within the receive limits')
      return
    end

    msg_type = data.byteslice(0, 3)
    body = data.byteslice(HEADER_LEN..)
    case msg_type
    when 'ACK'
      unless valid_ack?(body)
        vprint_status('Invalid OPC-UA ACK response')
        return
      end

      proto_ver, rcv_buf, snd_buf = body.unpack('V3')
      info = "ProtocolVersion=#{proto_ver} RecvBuf=#{rcv_buf} SendBuf=#{snd_buf}"
      print_good("OPC-UA server detected (ACK) - #{info}")
      report_service(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: 'opc-ua',
        info: "OPC-UA server (ACK): #{info}"
      )
    when 'ERR'
      unless valid_error?(body)
        vprint_status('Invalid OPC-UA ERR response')
        return
      end

      status, reason = decode_error(body)
      detail = reason.empty? ? status : "#{status} - #{reason}"
      print_good("OPC-UA server detected (ERR) - #{detail}")
      report_service(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: 'opc-ua',
        info: "OPC-UA server (ERR): #{detail}"
      )
    end
  ensure
    disconnect
  end

  private

  def read_response
    response = String.new.b
    expected_size = HEADER_LEN
    remaining = RECEIVE_TIMEOUT

    # TCP reads are not messages. Part 6 includes the header in MessageSize;
    # the Reserved byte is ignored by receivers, even though senders use 'F'.
    # https://reference.opcfoundation.org/specs/OPC-10000-6/7.1.2.2
    loop do
      return nil if remaining <= 0

      chunk, elapsed = Rex::Stopwatch.elapsed_time do
        sock.get_once(expected_size - response.bytesize, remaining)
      end
      remaining -= elapsed
      return nil if remaining.negative? || chunk.nil? || chunk.empty?

      response << chunk
      return nil if response.bytesize > expected_size

      if response.bytesize == HEADER_LEN && expected_size == HEADER_LEN
        return nil unless %w[ACK ERR].include?(response.byteslice(0, 3))

        expected_size = response.byteslice(4, 4).unpack1('V')
        return nil unless expected_size >= HEADER_LEN && expected_size < BUFFER_SIZE
      end
      return response if response.bytesize == expected_size
    end
  end

  def valid_ack?(body)
    # Five UInt32 fields; version and buffers must satisfy the sent HEL.
    # https://reference.opcfoundation.org/specs/OPC-10000-6/7.1.2.4
    return false unless body.bytesize == 20

    protocol, receive_buffer, send_buffer = body.unpack('V3')
    protocol.zero? && receive_buffer.between?(8192, BUFFER_SIZE) && send_buffer.between?(8192, BUFFER_SIZE)
  end

  def valid_error?(body)
    return false if body.bytesize < 8

    reason_length = body.byteslice(4, 4).unpack1('l<')
    return false if reason_length < -1

    body.bytesize == 8 + [reason_length, 0].max
  end
end
