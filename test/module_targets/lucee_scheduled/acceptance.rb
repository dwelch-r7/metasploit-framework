# frozen_string_literal: true

require 'ipaddr'
require 'webrick'
require_relative '../lucee/acceptance'

# Real admin authentication and scheduling are separate native prerequisites.
module LuceeScheduledTarget
  include LuceeTarget

  PASSWORD = 'module-target-admin-password'

  def laravel_owner
    'exploit/multi/http/lucee_scheduled_job'
  end

  def configure_admin
    expect(native('configure', { password: PASSWORD }, 'configure-web-admin')).to include('configured' => true)
    response = lucee_http('native-valid-login', '/lucee/admin/web.cfm', 'login_passwordweb' => PASSWORD, 'lang' => 'en', 'rememberMe' => 's', 'submit' => 'submit')
    expect(response.code).to eq('200')
    expect(response.body).to include('nav_Security', '/var/www')
    output, = rc_command('native-host-route', 'target', 'getent', 'ahostsv4', 'host.docker.internal')
    @listener_host = output.split.first
    expect(IPAddr.new(@listener_host).ipv4?).to be(true)
    listener = TCPServer.new('0.0.0.0', 0)
    @srvport = listener.addr[1]
  ensure
    listener&.close
  end

  def publisher_control
    task = "module_target_lucee_publisher_#{Process.pid}"
    path = '/var/www/' + task + '.cfm'
    source_path = '/' + task + '.cfm'
    source = '<cfoutput>lucee-native-schedule</cfoutput>'
    served = []
    expect(file(path)).to eq('exists' => false)
    server = WEBrick::HTTPServer.new(BindAddress: '0.0.0.0', Port: 0, AccessLog: [], Logger: WEBrick::Log.new(File::NULL))
    server.mount_proc(source_path) do |request, response|
      served << { path: request.path, query: request.query_string, peer: request.peeraddr[3] }
      response['Content-Type'] = 'text/plain'
      response.body = source
    end
    thread = Thread.new { server.start }
    thread.report_on_exception = false
    rc_poll(5) { server.status == :Running }
    origin = "http://#{@listener_host}:#{server.listeners.first.addr[1]}#{source_path}"
    native('schedule', { task: task, source: origin }, 'native-schedule-create-run')
    expected = { 'exists' => true, 'uid' => 0, 'base64' => Base64.strict_encode64(source) }
    observed = rc_poll(10) do
      value = file(path)
      value if value == expected
    end
    response = lucee_http('native-schedule-execute', '/' + task + '.cfm')
    expect(response.code).to eq('200')
    expect(response.body.strip).to eq('lucee-native-schedule')
    expect(native('verify', {}, 'native-schedule-visible').fetch('jobs')).to include(task)
    expect(served).not_to be_empty
    expect(served).to all(include(path: source_path, query: 'RequestTimeout=10'))
    @rc[:publisher] = { task: task, path: path, source_base64: Base64.strict_encode64(source), served: served, proof: observed, executed: true }
  ensure
    primary = $ERROR_INFO
    begin
      jobs = native('verify', {}, 'native-schedule-cleanup-list').fetch('jobs')
      native('delete', { task: task }, 'native-schedule-delete') if jobs.include?(task)
      remove_file(path) if path
      expect(native('verify', {}, 'native-schedule-cleaned').fetch('jobs')).to eq([])
      server&.shutdown
      thread&.join(5)
      expect(thread&.alive?).not_to be(true)
    rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
      (@rc[:cleanup_errors] ||= []) << { type: e.class.name, message: e.message }
      raise unless primary
    ensure
      server&.shutdown
      thread&.join(5)
      rc_save
    end
  end

  def listener_closed
    socket = TCPServer.new('0.0.0.0', @srvport)
    true
  rescue Errno::EADDRINUSE
    false
  ensure
    socket&.close
  end

  def owner_options(password = PASSWORD)
    { 'TARGET' => 1, 'PAYLOAD' => 'cmd/unix/generic', 'PASSWORD' => password, 'SRVHOST' => '0.0.0.0', 'SRVPORT' => @srvport, 'URIHOST' => @listener_host, 'PAYLOAD_DEPLOY_TIMEOUT' => 10, 'AllowNoCleanup' => true, 'DisablePayloadHandler' => true, 'WfsDelay' => 0, 'HttpClientTimeout' => 15 }
  end

  def owner_commands(kind, content)
    2.times do |iteration|
      path = "/tmp/module-target-lucee-scheduled-owner-#{Process.pid}-#{kind}-#{iteration}"
      command = 'printf %s ' + Shellwords.escape(content) + ' >> ' + path
      native_control(command, path, content)
      expect(listener_closed).to be(true)
      console_command('back') if iteration.zero?
      console_command('use ' + laravel_owner) if iteration.zero?
      rc_json("begin;active_module.datastore['CMD']=#{command.inspect};true;end")
      offset = rc_json('framework.instance_variable_get(:@lucee_events).length')
      options = owner_options
      output = run_target_module(laravel_owner, 'target', options, action: 'run -z', reuse_module: true, allow_errors: true)
      selection = rc_json('active_module.object_id')
      expect(selection).to eq(@selected_owner) if iteration.positive?
      @selected_owner = selection
      events = rc_json("framework.instance_variable_get(:@lucee_events).drop(#{offset})")
      physical = rc_poll(5) do
        value = file(path)
        value if value.fetch('exists')
      end
      jobs = native('verify', {}, 'owner-jobs-after').fetch('jobs')
      tasks = events.select { |row| row['event'] == 'call' && row['method'] == 'create_job' }.map { |row| row.fetch('task') }
      stubs = events.filter_map { |row| row['stub_base64'] }
      @rc[:calls] << { kind: kind, iteration: iteration, options: options, command_base64: Base64.strict_encode64(command.b), output: output, selection: selection, events: events, proof: physical, jobs_after: jobs, listener_closed: listener_closed }
      rc_save
      expect(physical).to eq('exists' => true, 'uid' => 0, 'base64' => Base64.strict_encode64(content.b))
      expect(tasks.length).to eq(1)
      expect(stubs).not_to be_empty
      stub = '/var/www/' + tasks.first + '.cfm'
      actual_stub = file(stub)
      expect(actual_stub).to eq('exists' => true, 'uid' => 0, 'base64' => stubs.last)
      stubs.each do |encoded|
        payload = Base64.strict_decode64(encoded)[%r{binaryDecode\("([A-Za-z0-9+/=]+)",\s*"base64"\)}, 1]
        expect(payload).to eq(Base64.strict_encode64(command.b))
      end
      @rc[:calls].last[:stub] = { path: stub, proof: actual_stub }
      expect(jobs).to eq([])
      expect(listener_closed).to be(true)
      expect(output).not_to include('Exploit failed', 'Exploit aborted')
    ensure
      primary = $ERROR_INFO
      begin
        cleanup_events = rc_json("framework.instance_variable_get(:@lucee_events).drop(#{offset || 0})")
        jobs = native('verify', {}, 'fixture-cleanup-list').fetch('jobs')
        cleanup_events.select { |row| row['event'] == 'call' && row['method'] == 'create_job' }.each do |row|
          task = row.fetch('task')
          native('delete', { task: task }, 'fixture-cleanup-task') if jobs.include?(task)
          remove_file('/var/www/' + task + '.cfm')
        end
        remove_file(path) if path
        expect(native('verify', {}, 'fixture-cleanup-complete').fetch('jobs')).to eq([])
      rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
        (@rc[:cleanup_errors] ||= []) << { type: e.class.name, message: e.message }
        raise unless primary
      ensure
        rc_save
      end
    end
  end

  def wrong_password
    expect(listener_closed).to be(true)
    offset = rc_json('framework.instance_variable_get(:@lucee_events).length')
    options = owner_options('module-target-wrong-password')
    output = run_target_module(laravel_owner, 'target', options, action: 'run -z', allow_errors: true)
    events = rc_json("framework.instance_variable_get(:@lucee_events).drop(#{offset})")
    @rc[:calls] << { kind: 'wrong-password', options: options, output: output, events: events }
    expect(output).to include('Unable to authenticate. Please double check your credentials and try again.')
    expect(events.select { |row| %w[create_job execute_job cfm_stub].include?(row['method']) }).to eq([])
    expect(native('verify', {}, 'wrong-password-jobs').fetch('jobs')).to eq([])
    expect(listener_closed).to be(true)
  end
end
