# frozen_string_literal: true

require_relative '../rsync_creds/native'

# Genuine WebDriver controls and owning command execution; no browser doubles.
module SeleniumExecutionTarget
  include RsyncCredentialTarget

  def sg_profile_key
    ENV.fetch('SELENIUM_GREED_PROFILE', 'firefox4')
  end

  def sg_profile
    @sg_profile ||= JSON.parse(File.read(File.expand_path('../selenium_file/profiles.json', __dir__))).fetch(sg_profile_key)
  end

  def sg_legacy?
    sg_profile.fetch('version').start_with?('3.')
  end

  def sg_browser_choice
    sg_legacy? ? 'firefox' : 'auto'
  end

  def sg_target_uri
    sg_legacy? ? '/wd/hub/' : '/'
  end

  def rc_owner
    'exploit/linux/http/selenium_greed_rce'
  end

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'selenium-execution.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    ['target']
  end

  def sg_trace_start
    code = <<~RUBY
      begin
        rows = []
        source = File.realpath('modules/exploits/linux/http/selenium_greed_rce.rb')
        methods = %i[check exploit]
        trace = TracePoint.new(:call) do |event|
          next unless methods.include?(event.method_id) && File.expand_path(event.path) == source

          rows << { method: event.method_id, object_id: event.self.object_id, path: event.path, line: event.lineno }
        end
        framework.instance_variable_set(:@module_target_selenium_trace, rows)
        framework.instance_variable_set(:@module_target_selenium_tracepoint, trace)
        trace.enable
        { installed: true }
      end
    RUBY
    expect(rc_json(code.lines.map(&:strip).reject(&:empty?).join(';'))).to eq('installed' => true)
  end

  def sg_trace_finish
    @rc[:owner_trace] = rc_json('begin;trace=framework.instance_variable_get(:@module_target_selenium_tracepoint);trace.disable if trace;framework.instance_variable_get(:@module_target_selenium_trace);end')
    rc_save
  end

  def sg_control(phase)
    directory = File.join(target_runtime.fetch('artifacts'), 'native-' + phase)
    Dir.mkdir(directory)
    runtime = { directory: directory, compose: target_runtime.fetch('compose'), port: target_endpoint('target').fetch('port'), stamp: "#{Process.pid}-#{phase}", profile: sg_profile }
    path = File.join(directory, 'runtime.json')
    File.write(path, JSON.pretty_generate(runtime))
    argv = ['python3', File.expand_path('native_control.py', __dir__), path]
    output, error, status = Open3.capture3(*argv)
    @rc.fetch(:commands) << { label: 'native-' + phase, argv: argv, exit: status.exitstatus, stdout_base64: Base64.strict_encode64(output.b), stderr: error }
    data = JSON.parse(File.read(File.join(directory, 'native.json')))
    @rc.fetch(:native) << { phase: phase, data: data }
    rc_save
    expect(status.success?).to be(true), output + error
    expect(data.values_at('passed', 'ordinary_browser_passed', 'external_handler_passed', 'owner_calls')).to eq([true, true, true, 0])
    data
  end

  def sg_browser_state
    code = <<~PYTHON
      import json,sys,urllib.request
      base = 'http://127.0.0.1:' + sys.argv[1]
      legacy = sys.argv[2] == 'true'
      def request(path):
          return json.load(urllib.request.urlopen(base + path, timeout=10))['value']
      value = request('/wd/hub/status' if legacy else '/status')
      sessions = [row['id'] for row in request('/wd/hub/sessions')] if legacy else [slot['session']['sessionId'] for node in value['nodes'] for slot in node['slots'] if slot['session']]
      print(json.dumps({'ready': value['ready'], 'status': value, 'sessions': sessions}))
    PYTHON
    output, error, status = Open3.capture3('python3', '-c', code, target_endpoint('target').fetch('port').to_s, sg_legacy?.to_s)
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def sg_marker
    code = "from pathlib import Path;import base64,json,sys;p=Path(sys.argv[1]);print(json.dumps({'exists':p.is_file(),'base64':base64.b64encode(p.read_bytes()).decode() if p.is_file() else None,'uid':p.stat().st_uid if p.exists() else None}))"
    output, = rc_command('owner-marker', 'target', 'python3', '-c', code, @marker)
    JSON.parse(output)
  end

  def sg_remove_marker
    return unless @marker

    code = "from pathlib import Path;import json,sys;p=Path(sys.argv[1]);assert p.parent==Path('/tmp') and p.name.startswith('module-target-selenium-owner-');present=p.exists();\nif present:\n assert p.stat().st_uid==1200 and p.read_bytes()==b'owner-canary';p.unlink()\nprint(json.dumps({'was_present':present,'absent':not p.exists()}))"
    output, = rc_command('remove-owner-marker', 'target', 'python3', '-c', code, @marker)
    @rc[:marker_recovery] = JSON.parse(output)
    rc_save
  end
end
