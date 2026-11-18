# frozen_string_literal: true

require_relative '../rsync_creds/native'

# Real application controls and persisted credential origins for SuiteCRM.
module SuiteCrmTarget
  include RsyncCredentialTarget

  OWNER = 'auxiliary/gather/suite_crm_export_sqli'

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'suitecrm.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    %w[app db reporting_db]
  end

  def sc_native(phase)
    argv = ['python3', '-B', 'test/module_targets/suitecrm/native.py', ENV.fetch('MODULE_TARGET_RUNTIME'), phase]
    output, error, status = Open3.capture3(*argv)
    @rc.fetch(:native) << { phase: phase, argv: argv, stdout: output, stderr: error, exit: status.exitstatus }
    rc_save
    expect(status.success?).to be(true), output + error
    data = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), 'native-suitecrm-' + phase + '.json')))
    expect(data.fetch('status')).to eq('passed')
    data.fetch('snapshot')
  end

  def sc_reports
    expect(@workspace).to match(/\Asc_\d+_[a-z]+\z/)
    data = JSON.parse(rc_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.username),'[]'::json) FROM (
        SELECT p.username,secret.data AS private_data,secret.type,secret.jtr_format,
          c.origin_type,origin.module_full_name,service.name AS service,service.port,
          service.proto,host(host.address::inet) AS address
        FROM metasploit_credential_cores c JOIN workspaces workspace ON workspace.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id
        LEFT JOIN metasploit_credential_privates secret ON secret.id=c.private_id
        LEFT JOIN metasploit_credential_origin_services origin ON origin.id=c.origin_id
          AND c.origin_type='Metasploit::Credential::Origin::Service'
        LEFT JOIN services service ON service.id=origin.service_id
        LEFT JOIN hosts host ON host.id=service.host_id
        WHERE workspace.name='#{@workspace}'
      ) row
    SQL
    @rc.fetch(:reports) << { workspace: @workspace, rows: data }
    rc_save
    data
  end

  def sc_call(label, options = {}, action: 'run', reuse: false, expected_method: action, allow_failure: false, timeout: 600)
    count = rc_json('framework.instance_variable_get(:@suitecrm_events).length')
    record = { label: label, action: action, options: options }
    @rc.fetch(:calls) << record
    values = { 'USERNAME' => 'labadmin', 'PASSWORD' => 'Module-suite-admin42!', 'HttpClientTimeout' => 10, 'AutoCheck' => true }.merge(options)
    values['COUNT'] = 3 if reuse && !options.key?('COUNT')
    output = run_target_module(OWNER, 'app', values, action: action, allow_errors: true, reuse_module: reuse, command_timeout: timeout) do |text|
      record[:output_base64] = Base64.strict_encode64(text.b)
      record[:events] = rc_json('framework.instance_variable_get(:@suitecrm_events)').drop(count)
      rc_save
    end
    record[:credentials] = sc_reports
    record[:identity] = rc_json('active_module.object_id')
    rc_save
    expect(record.fetch(:events)).to include(include('event' => 'call', 'method' => expected_method))
    expect(output).not_to match(/Call stack:|Error while running command|Unknown datastore option/)
    expect(output).not_to match(/Auxiliary failed|Auxiliary aborted/) unless allow_failure
    [output, record]
  end

  def sc_refusal(label, options = {}, reuse: false)
    output, record = sc_call(label, options.merge('AutoCheck' => true), reuse: reuse, expected_method: 'check', allow_failure: true, timeout: 60)
    expect(record.fetch(:credentials)).to eq([])
    expect(record.fetch(:events)).not_to include(include('event' => 'call', 'method' => 'run'))
    expect(record.fetch(:events)).to include(include('event' => 'return', 'method' => 'check', 'result' => include('code' => 'safe')))
    expect(output).to match(/not-vulnerable|not vulnerable/i)
    record
  end

  def sc_success(record, count:)
    expected = @baseline.fetch('users').sort_by { |row| row.fetch('user_name') }.first(count)
    rows = record.fetch(:credentials)
    expect(rows.length).to eq(expected.length)
    names = record.fetch(:events).find { |event| event.values_at('event', 'method') == %w[return get_user_names] }.fetch('names_base64')
    expect(names.map { |name| Base64.strict_decode64(name) }).to eq(expected.map { |row| row.fetch('user_name') })
    expect(rows.to_h { |row| row.values_at('username', 'private_data') }).to eq(expected.to_h { |row| row.values_at('user_name', 'user_hash') })
    endpoint = target_endpoint('app')
    rows.each do |row|
      expect(row.values_at('type', 'jtr_format', 'origin_type', 'module_full_name', 'port', 'proto', 'address')).to eq(['Metasploit::Credential::NonreplayableHash', 'bf', 'Metasploit::Credential::Origin::Service', OWNER, endpoint.fetch('port'), 'tcp', endpoint.fetch('host')])
      expect(row.fetch('service').downcase).to eq('suitecrm')
    end
  end
end
