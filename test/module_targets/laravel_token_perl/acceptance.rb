# frozen_string_literal: true

require_relative '../laravel_token/acceptance'
require_relative '../laravel/sessions'

# Preserve the legacy owner's options while using the common lifecycle gates.
module LaravelTokenSessions
  include LaravelTokenTarget
  include LaravelSessions

  FAMILIES = { 'perl-shell' => [0, 'cmd/unix/reverse_perl', 'shell'] }.freeze

  def session_families
    FAMILIES
  end

  def session_exec_options
    ['--user', 'www-data']
  end

  def session_default_options
    { 'perl-shell' => %w[TARGET PAYLOAD] }
  end

  def session_owner_options(options)
    options.except('AutoCheck', 'ForceExploit').merge('APP_KEY' => LaravelTokenTarget::KEY)
  end

  def session_control_name
    'LaravelTokenSessionControl'
  end

  def session_health_path
    '/index.php'
  end

  def native_session(family)
    rc_command('native-perl-availability', 'target', 'sh', '-c', 'command -v perl')
    super
  end

  def use_session(family, attempt, owner)
    unless owner == laravel_owner
      super
      return true
    end

    events = rc_json('framework.instance_variable_get(:@laraveltoken_events)')
    generated = events.drop(@rc.fetch(:legacy_event_cursor, 0)).select { |event| event['event'] == 'call' && event['method'] == 'generate_token' }.map { |event| event.fetch('gadget') }
    @rc[:legacy_event_cursor] = events.length
    expect(generated).not_to be_empty
    expect(generated).to eq((1..generated.last).to_a)
    expected = (generated & LaravelTokenTarget::WORKING_METHODS).length
    expect(expected).to be_between(1, 3)
    attempt[:gadget_methods] = generated
    attempt[:expected_sessions] = expected
    payload = session_families.fetch(family)[1]
    metadata = rc_poll(45) do
      ready = File.readlines(@ready.fetch('ready_event_path')).filter_map do |line|
        JSON.parse(line).fetch('id')
      rescue JSON::ParserError
        nil
      end
      rows = rc_json('framework.sessions.map{|id,session|{id:id,type:session.type,owner:session.via_exploit,payload:session.via_payload,db_id:session.db_record&.id}}')
      admitted = rows.select { |row| row['owner'] == owner && row['payload'] == 'payload/' + payload }
      admitted if admitted.length == expected && admitted.all? { |row| ready.include?(row.fetch('id')) && row['db_id'] }
    end
    members = metadata.map { |row| { metadata: row } }
    attempt[:members] = members
    paths = []
    members.each do |member|
      row = member.fetch(:metadata)
      expect(row.fetch('type')).to eq('shell')
      path = "/tmp/module-target-laraveltoken-session-#{Process.pid}-#{row.fetch('id')}"
      paths << path
      expect(file(path)).to include('exists' => false)
      member[:proof] = rc_json("#{session_control_name}.proof(framework,#{row.fetch('id')},#{path.inspect},'laraveltoken-session',false)")
      expect(member.fetch(:proof).fetch('db_id')).to eq(row.fetch('db_id'))
      expect(file(path)).to eq('exists' => true, 'uid' => laravel_uid, 'base64' => Base64.strict_encode64('laraveltoken-session'))
      state = process_state
      process = state.fetch('processes').find { |entry| entry.fetch('pid') == member.fetch(:proof).fetch('pid') }
      expect(process).to include('uid' => laravel_uid.to_s)
      expect(@baseline.fetch('processes').map { |entry| entry.fetch('pid') }).not_to include(process.fetch('pid'))
      expect(state.fetch('connections').count { |entry| entry.fetch('state') == '01' }).to eq(expected)
      member[:live_state] = state
      member[:open_reports] = session_rows
      expect(member.fetch(:open_reports)).to include(include('id' => row.fetch('db_id'), 'via_exploit' => owner, 'via_payload' => 'payload/' + payload, 'closed_at' => nil))
      expect(http(session_health_path).code).to eq('200')
      rc_save
    end
    expect(members.map { |member| member.fetch(:proof).fetch('pid') }.uniq.length).to eq(expected)
    members.each do |member|
      member[:shutdown] = rc_json("#{session_control_name}.shutdown(framework,#{member.fetch(:metadata).fetch('id')})")
    end
    tracked = members.map do |member|
      member.fetch(:live_state).fetch('processes').find { |row| row.fetch('pid') == member.fetch(:proof).fetch('pid') }.values_at('pid', 'birth')
    end
    rc_poll(15) { process_state.fetch('processes').none? { |row| tracked.include?(row.values_at('pid', 'birth')) } }
    console_command('jobs -K')
    settled
    reports = session_rows
    members.each do |member|
      member[:closed_reports] = reports
      expect(reports).to include(include('id' => member.fetch(:metadata).fetch('db_id'), 'closed_at' => be_a(String)))
    end
    true
  ensure
    primary = $ERROR_INFO
    begin
      (paths || []).each do |path|
        rc_command('remove-session-proof', 'target', 'rm', '-f', '--', path)
        expect(file(path)).to include('exists' => false)
      end
    rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
      attempt[:cleanup_error] = { type: e.class.name, message: e.message }
      raise unless primary
    ensure
      rc_save
    end
  end
end
