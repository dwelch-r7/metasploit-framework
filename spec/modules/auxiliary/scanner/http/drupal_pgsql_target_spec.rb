require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/drupal_pgsql/acceptance'

RSpec.describe 'Native Drupal PostgreSQL EntityQuery detection', acceptance: true, order: :defined do
  include_context 'native Drupal PostgreSQL target'

  profile = DrupalPgsqlProfiles.fetch
  if %w[affected fixed unaffected].include?(profile.fetch('mode'))
    vulnerable = 'Time-based blind SQL injection via JSON:API filter array key'
    safe = 'No time-based SQL injection response detected'
    expected = profile.fetch('mode') == 'affected' ? vulnerable : safe

    it 'detects the native boundary twice with the title field' do
      options = ENV.fetch('DRUPAL_PGSQL_PROFILE', 'drupal_pgsql') == 'drupal_pgsql' ? { 'SqliDelay' => 3.0 } : {}
      2.times { drpg_run(options, expected: expected, service_report: true) }
    end

    it 'handles a custom case-insensitive string field twice' do
      2.times { drpg_run({ 'JSONAPI_FIELD' => 'field_module_marker' }, expected: expected, service_report: true) }
    end

    it 'rejects a case-sensitive field twice without a vulnerability report' do
      2.times { drpg_run({ 'JSONAPI_FIELD' => 'field_case_marker' }, expected: safe, service_report: true) }
    end

    if ENV.fetch('DRUPAL_PGSQL_PROFILE', 'drupal_pgsql') == 'drupal_pgsql'
      it 'reports a fresh explicit check twice without a prior run' do
        2.times { drpg_owner(expected: vulnerable, service_report: true, action: 'check') }
      end

      it 'accepts a shorter positive fractional delay twice' do
        2.times { drpg_run({ 'SqliDelay' => 0.4 }, expected: vulnerable, service_report: true) }
      end

      it 'rejects a nonexistent field twice before reporting a service' do
        2.times { drpg_run({ 'JSONAPI_FIELD' => 'field_module_missing' }, expected: "JSONAPI_FIELD 'field_module_missing' is not valid for this resource", service_report: false) }
      end

      it 'handles a nonexistent resource twice without a vulnerability report' do
        2.times { drpg_run({ 'JSONAPI_RESOURCE' => 'module_missing/no_bundle' }, expected: '/jsonapi/module_missing/no_bundle returned HTTP 404', service_report: false) }
      end

      it 'handles a readable empty resource twice without a vulnerability report' do
        2.times { drpg_run({ 'JSONAPI_RESOURCE' => 'taxonomy_term/tags' }, expected: 'taxonomy_term/tags has no entities', service_report: false) }
      end

      it 'handles the wrong installation path twice' do
        2.times { drpg_run({ 'TARGETURI' => '/module-target-missing/' }, expected: '/module-target-missing/jsonapi/node/article returned HTTP 404', service_report: false) }
      end

      it 'handles a rejected virtual host twice' do
        2.times { drpg_run({ 'VHOST' => 'module-target.invalid' }, expected: '/jsonapi/node/article returned HTTP 400', service_report: false) }
      end

      it 'handles a refused connection twice without reporting a service' do
        socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
        socket.bind(Socket.sockaddr_in(0, '127.0.0.1'))
        port = Socket.unpack_sockaddr_in(socket.getsockname).first
        2.times { drpg_run({ 'RPORT' => port }, expected: 'No response to the baseline JSON:API request', service_report: false) }
      ensure
        socket&.close
      end
    end
  else
    it 'handles the missing deployment prerequisite twice without a vulnerability report' do
      expected = case profile.fetch('mode')
                 when 'empty', 'private' then 'node/article has no entities'
                 else '/jsonapi/node/article returned HTTP 404'
                 end
      2.times { drpg_run(expected: expected, service_report: false) }
    end
  end
end
