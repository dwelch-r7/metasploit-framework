# frozen_string_literal: true

require_relative '../laravel/sessions'
require_relative '../opendcim/acceptance'

# Session readiness is independent of the vulnerable application's delivery.
module OpenDcimSessions
  include LaravelSessions
  include OpenDcimTarget

  def laravel_component
    'opendcim'
  end

  def laravel_owner
    OpenDcimTarget::OWNER
  end

  def laravel_uid
    33
  end

  def session_control_name
    'OpenDcimSessionControl'
  end

  def session_families
    { 'bash-shell' => [0, 'cmd/unix/reverse_bash', 'shell'] }
  end

  def session_default_options
    {}
  end

  def session_exec_options
    ['--user', '33']
  end

  def session_health_path
    '/index.php'
  end

  def session_owner_options(options)
    # Observe the real HttpClient default rather than Laravel's three seconds.
    options.except('HttpClientTimeout')
  end

  def rc_resource_roles
    %w[target database reporting_db]
  end

  def idle
    expect(rc_json('framework.sessions.keys')).to eq([])
    expect(rc_json('framework.jobs.keys')).to eq([])
    expect(session_rows).to all(include('closed_at' => be_a(String))) if @workspace
    state = process_state
    @rc[:states] << { phase: 'idle', state: state }
    rc_save
    expect(state.fetch('connections')).to eq([])
    # Apache may add idle prefork workers during a foreground shell. Retain
    # their real identity but allow only ordinary children of the original root.
    worker = lambda do |row|
      row.fetch('uid') == '33' && row.fetch('command') == '/usr/sbin/apache2 -D FOREGROUND'
    end
    baseline = @baseline.fetch('processes')
    parents = baseline.select { |row| row.fetch('uid') == '0' && row.fetch('command') == '/usr/sbin/apache2 -D FOREGROUND' }.map { |row| row.fetch('pid') }
    expect(parents.length).to eq(1)
    expect(state.fetch('processes').select(&worker)).to all(include('ppid' => parents.first))
    expect(state.fetch('processes').reject(&worker).map { |row| row.except('state') }).to eq(baseline.reject(&worker).map { |row| row.except('state') })
    true
  end

  def os_ready
    @rc[:readiness] = od_native('before')
    expect(@rc.fetch(:readiness)).to include('passed' => true, 'version' => '24.01', 'uid' => 33)
    tools, error, status = Open3.capture3(*session_exec_argv('php', '-r', <<~PHP))
      $out=['uid'=>posix_getuid(),'tools'=>[]];
      foreach(['bash','curl','wget'] as $tool){
        $out['tools'][$tool]=trim(shell_exec('command -v '.escapeshellarg($tool).' 2>/dev/null')??'');
      }
      echo json_encode($out,JSON_THROW_ON_ERROR);
    PHP
    @rc[:tools] = { exit: status.exitstatus, stderr: error, observed: JSON.parse(tools) }
    rc_save
    expect(status.success?).to be(true), error
    expect(@rc.fetch(:tools).fetch(:observed)).to eq('uid' => 33, 'tools' => { 'bash' => '/usr/bin/bash', 'curl' => '', 'wget' => '' })
    rc_resources('before')
    @rc[:observer] = rc_json("begin;load 'test/module_targets/opendcim/observe.rb';OpenDcimObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    @baseline = process_state
    expect(@baseline.fetch('connections')).to eq([])
    callback_control
    endpoint = target_endpoint('reporting_db')
    expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    @ready = rc_json("begin;load 'test/module_targets/opendcim_sessions/session_control.rb';OpenDcimSessionControl.install(framework);end")
    @rc[:session_context] = { baseline: @baseline, listener_host: @listener_host, ready: @ready }
    @rc[:prepared] = true
    od_registry
  end

  def use_session(family, attempt, owner)
    super
    od_registry
  end

  def owner_session(family)
    offset = rc_json('framework.instance_variable_get(:@opendcim_events).length')
    super
    events = rc_json("framework.instance_variable_get(:@opendcim_events).drop(#{offset})")
    @rc[:calls] << { family: family, events: events }
    rc_save
    expect(events.count { |row| row['owner_exploit_body'] }).to eq(2)
    expect(events.filter_map { |row| row['check'] }).to eq([{ 'code' => 'vulnerable', 'reason' => 'Successfully tested SQL injection (3/3 delay checks passed).' }])
    backups = events.select { |row| row['event'] == 'call' && row['method'] == 'backup_config' }.map { |row| row.fetch('backup_table') }
    expect(backups.length).to eq(2)
    expect(backups.uniq.length).to eq(2)
  ensure
    rc_save
  end
end
