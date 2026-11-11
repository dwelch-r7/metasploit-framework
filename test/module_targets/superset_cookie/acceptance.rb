# frozen_string_literal: true

require 'base64'
require_relative '../../../tools/dev/run_module_target_tests'

RSpec.shared_context 'Superset cookie owner evidence' do
  include_context 'module target'

  def inspect_cookie(output, mode)
    cookie = output[/New signed cookie: session=(\S+)/, 1]
    expect(cookie).not_to be_nil, output
    path = File.join(target_runtime.fetch('artifacts'), "owner-cookie-#{mode}.log")
    argv = ['python3', '-B', 'test/module_targets/superset_cookie/inspect_cookie.py', ENV.fetch('MODULE_TARGET_RUNTIME'), mode, cookie]
    expect(ModuleTargetTests.new.send(:command, argv, path: path, timeout: 90, quiet: true)).to be(true)
    JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "owner-cookie-#{mode}/result.json")))
  end

  def gather_options
    { 'USERNAME' => 'lab-user', 'PASSWORD' => 'module-target-superset-user-password', 'SECRET_KEYS_FILE' => @keys }
  end

  def native_phase(phase)
    output = +''
    path = File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log")
    runner = ModuleTargetTests.new
    argv = ['python3', '-B', 'test/module_targets/superset_cookie/native_runtime.py', ENV.fetch('MODULE_TARGET_RUNTIME'), phase]
    passed = runner.send(:command, argv, path: path, timeout: 240, capture: output, quiet: true)
    expect(passed).to be(true), output
  end

  def credential_rows
    query = <<~SQL
      SELECT coalesce(json_agg(row), '[]'::json) FROM (
        SELECT c.id, l.id AS login_id, p.username, secret.data AS password,
               host(h.address::inet) AS host, s.id AS service_id, s.port, s.name AS service, l.status, l.last_attempted_at, w.name AS workspace,
               c.origin_type, o.module_full_name, o.service_id AS origin_service_id,
               c.workspace_id AS credential_workspace_id, h.workspace_id AS host_workspace_id
        FROM metasploit_credential_cores c
        JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id
        LEFT JOIN metasploit_credential_privates secret ON secret.id=c.private_id
        LEFT JOIN metasploit_credential_logins l ON l.core_id=c.id
        LEFT JOIN services s ON s.id=l.service_id
        LEFT JOIN hosts h ON h.id=s.host_id
        LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
        WHERE w.name='#{@workspace}' ORDER BY c.id,l.id
      ) row
    SQL
    JSON.parse(target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query))
  end
end
