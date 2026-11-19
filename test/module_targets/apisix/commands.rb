# frozen_string_literal: true

require 'shellwords'
require_relative '../rsync_creds/native'

# Compare independent native state with real console owner execution and cleanup.
module ApisixTarget
  include RsyncCredentialTarget

  OWNER = 'exploit/multi/http/apache_apisix_api_default_token_rce'

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'apisix.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    ENV.fetch('APISIX_SESSIONS', 'false') == 'true' ? %w[app reporting_db] : %w[app]
  end

  def ap_native(operation, *arguments)
    argv = ['python3', 'test/module_targets/apisix/native.py', ENV.fetch('MODULE_TARGET_RUNTIME'), operation, *arguments]
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { argv: argv, operation: operation, stdout: output, stderr: error, exit: status.exitstatus }
    rc_save
    raise "Native prerequisite failed: #{operation}: #{output}: #{error}" unless status.success?

    JSON.parse(output.match(/^APISIX_NATIVE=(.+)$/)[1]).fetch('result')
  end

  def ap_events
    rc_json('framework.instance_variable_get(:@apisix_events)')
  end

  def ap_check(options = {}, endpoint: nil)
    offset = ap_events.length
    record = { options: options, endpoint: endpoint }
    @rc[:calls] << record
    record[:output] = run_target_module('exploit/multi/http/apache_apisix_api_default_token_rce', 'app', options, endpoint_options: endpoint, action: 'check', allow_errors: true) do |output|
      record[:output] = output
    end
    record[:checks] = ap_events.drop(offset).select { |event| event['event'] == 'return' && event['method'] == 'check' }
    record[:checks]
  ensure
    record[:events] = ap_events.drop(offset) if record && offset
    rc_save
  end

  def ap_command(label, contents, reuse: false)
    baseline = @rc.fetch(:identity).fetch('inventory')
    expect(ap_native('inventory')).to eq(baseline)
    path = '/tmp/module-target-apisix-owner-' + label
    expect(ap_native('file', path)).to eq('exists' => false)
    shell = 'printf %s ' + Shellwords.escape(contents) + ' >> ' + path
    # Native decimal-byte construction executes this exact shell command first.
    ap_native('command', shell, path, Base64.strict_encode64(contents.b))
    unless reuse
      console_command('back')
      expect(console_command('use ' + OWNER)).not_to include('Failed to load')
    end
    expect(console_command('set PAYLOAD cmd/unix/generic')).not_to include('[-]')
    expect(rc_json("begin;active_module.datastore['CMD']=#{shell.inspect};active_module.datastore['CMD'];end")).to eq(shell)
    offset = ap_events.length
    record = { label: label, command_base64: Base64.strict_encode64(shell.b), baseline: baseline }
    @rc[:calls] << record
    record[:output] = run_target_module('exploit/multi/http/apache_apisix_api_default_token_rce', 'app', {
      'API_KEY' => 'edd1c9f034335f136f87ad84b625c8f1', 'PAYLOAD' => 'cmd/unix/generic',
      'DisablePayloadHandler' => true, 'WfsDelay' => 0
    }, action: 'run -z', allow_errors: true, reuse_module: true) { |output| record[:output] = output }
    record[:events] = ap_events.drop(offset)
    record[:selection] = rc_json('active_module.object_id')
    expect(record[:selection]).to eq(@rc.fetch(:previous_command_selection)) if reuse
    @rc[:previous_command_selection] = record[:selection]
    record[:datastore_after] = rc_json('Base64.strict_encode64(active_module.datastore["CMD"].b)')
    expect(record[:datastore_after]).to eq(record[:command_base64])
    record[:file] = ap_native('file', path)
    record[:inventory] = ap_native('inventory')
    rc_save
    expected = ENV.fetch('APISIX_KIND') == 'fixed' ? { 'exists' => false } : { 'exists' => true, 'uid' => @rc.fetch(:identity).fetch('uid'), 'base64' => Base64.strict_encode64(contents.b) }
    aggregate_failures do
      expect(record[:file]).to eq(expected)
      expect(record[:inventory]).to eq(baseline)
      if ENV.fetch('APISIX_KIND') == 'fixed'
        attempted = record[:events].select { |event| event['event'] == 'call' && %w[add_route filter_func_exec].include?(event['method']) }
        expect(attempted).to be_empty
      end
    end
  ensure
    if record && offset
      record[:events] ||= ap_events.drop(offset)
      record[:file] ||= ap_native('file', path)
      record[:inventory] ||= ap_native('inventory')
    end
    ap_native('remove', path) if path
    ap_native('audit') if baseline
    rc_save
  end
end
