
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'packetfu'

class MetasploitModule < Msf::Auxiliary
  def initialize
    super(
        'Name'        => 'urgent11-detector - IPnet detection tool by Armis',
        'Description' => %q{
          This tool implements 4 unique methods of detection
        in the form of a TCP/IP stack fingerprints to a target host.
        By calculating the sum of all the methods scores, we can determine with
        high precision whether the target host runs some embedded OS
        that relies on the IPnet TCP/IP stack and whether that OS is VxWorks.

        Moreover we test the host for one of the URGENT/11 vulnerabilities,
        CVE-2019-12258.
      },
        'References'  =>
            [
                [ 'URL', 'https://armis.com/urgent11' ],
                [ 'URL', 'https://github.com/ArmisSecurity/urgent11-detector' ],
                [ 'CVE', '2019-12258']
            ],
        'Author'      => [
            'Ben Seri', # Upstream tool
            'Brent Cook' # Metasploit module
            ],
        'License'     => MSF_LICENSE,
        'Notes' =>
            {
                'AKA' => ['Urgent/11']
            }
    )

    register_options(
        [
            Opt::RPORT(80)
        ]
    )

  end

  # Config
  CFG_PACKET_TIMEOUT = 0.5
  CFG_RETRANSMISSION_RATE = 3

  # Consts
  TCP_OPTION_NOP = 1
  TCP_OPTION_MSS = 2
  TCP_OPTION_WNDSCL = 3
  TCP_RST_FLAG = 'R'
  TCP_SYN_FLAG = 'S'
  ICMP_TIMESTAMP_REPLY = 14
  ICMP_ECHO_REQUEST = 8
  ICMP_TIMESTAMP_REQUEST_TRUNCATED = ['0d00f2ff00000000'].pack('H*')

  def validate_flags(pkt, flag)
      return pkt['TCP'].flags.includes? flag
  end


  def validate_ports(pkt, src, dst)
      pkt['TCP'].sport == src and pkt['TCP'].dport == dst
  end


  def detect_tcp_malformed_options(dhost, dport)
    shost, sport = getsource(dhost)
    tcp_pkt = PacketFu::TCPPacket.new
    tcp_pkt.ip_saddr = shost
    tcp_pkt.ip_daddr = dhost
    tcp_pkt.tcp_sport = sport
    tcp_pkt.tcp_dport = dport
    tcp_pkt.tcp_header.tcp_options = 'MSS:1460,0,NOP,WS:0'

  end
end
