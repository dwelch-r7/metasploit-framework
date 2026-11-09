##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'HTTP WebDAV Website Content Scanner',
      'Description' => 'Detect webservers disclosing its content though WebDAV',
      'Author' => ['et'],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('PATH', [true, 'Path to use', '/']),
        OptEnum.new('DEPTH', [true, 'Collection depth to request', '1', ['0', '1', 'infinity']])
      ]
    )
  end

  def run_host(target_host)
    res = send_request_cgi(
      {
        'uri' => normalize_uri(datastore['PATH']),
        'method' => 'PROPFIND',
        'data' => '',
        'ctype' => 'text/xml',
        'headers' => { 'Depth' => datastore['DEPTH'] }
      }
    )
    unless res
      vprint_status('PROPFIND request did not receive a response')
      return
    end

    unless res.code == 207
      vprint_status("PROPFIND returned HTTP #{res.code}")
      return
    end

    document = res.get_xml_document
    unless document.errors.empty?
      vprint_status('PROPFIND response was not valid XML')
      return
    end

    # DAV prefixes vary by server; RFC 4918 identifies these elements by namespace.
    hrefs = document.xpath('/d:multistatus/d:response/d:href', 'd' => 'DAV:').map { |node| node.text.strip }
    hrefs.reject(&:empty?).uniq.each do |href|
      # Retain the single-element array stored by earlier versions of this module.
      path = [href]
      print_good("Found file or directory in WebDAV response (#{target_host}) #{path}")

      report_note(
        host: target_host,
        proto: 'tcp',
        sname: (ssl ? 'https' : 'http'),
        port: rport,
        type: 'WEBDAV_FILE_DIRECTORY',
        data: { path: path }
      )
    end
  rescue Rex::ConnectionError, Timeout::Error, Errno::EPIPE => e
    vprint_error("PROPFIND request failed: #{e.message}")
    elog('WebDAV PROPFIND request failed', error: e)
  end
end
