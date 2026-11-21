# frozen_string_literal: true

require_relative '../lucee/acceptance'

# Real context writes separate a fixed endpoint from broken CFML or permissions.
module LuceeFixedTarget
  include LuceeTarget

  def laravel_component
    'lucee-fixed'
  end

  def native_verify(label)
    value = native('verify', {}, label)
    expect(value).to eq(JSON.parse(File.read('test/module_targets/lucee_fixed/installed-5.3.7.47.json')))
    output, = rc_command(label + '-vendor-jar', 'target', 'sha256sum', '/usr/local/tomcat/lucee/lucee.jar')
    expect(output.split.first).to eq('da47c8fbd13cbfe12544d18009e4cf00d09499b34c362a6b2b0e8c95ff8dc114')
    value
  end

  def native_streams
    path = "/tmp/module-target-lucee-fixed-streams-#{Process.pid}"
    expect(file(path)).to eq('exists' => false)
    command = 'printf lucee-stdout; printf lucee-stderr >&2; printf streams > ' + path
    value = native('execute', { command_base64: Base64.strict_encode64(command) }, 'fixed-nonempty-streams')
    proof = file(path)
    @rc[:streams] = { command_base64: Base64.strict_encode64(command), path: path, value: value, proof: proof }
    rc_save
    expect(Base64.strict_decode64(value.fetch('output_base64'))).to eq('lucee-stdout')
    expect(Base64.strict_decode64(value.fetch('errors_base64'))).to eq('lucee-stderr')
    expect(proof).to eq('exists' => true, 'uid' => 0, 'base64' => Base64.strict_encode64('streams'))
  ensure
    remove_file(path) if path
    rc_save
  end

  def native_fixed_write
    filename = "module_target_lucee_fixed_#{Process.pid}.cfm"
    path = '/opt/lucee/web/context/' + filename
    source = '<cfoutput>lucee-fixed-context-write</cfoutput>'
    expect(file(path)).to eq('exists' => false)
    command = ': /tmp/module-target-lucee-fixed-write; printf %s ' + Shellwords.escape(source) + ' > ' + path
    value = native('execute', { command_base64: Base64.strict_encode64(command) }, 'fixed-context-write')
    expect(Base64.strict_decode64(value.fetch('output_base64'))).to eq('')
    expect(Base64.strict_decode64(value.fetch('errors_base64'))).to eq('')
    positive = file(path)
    expect(positive).to eq('exists' => true, 'uid' => 0, 'base64' => Base64.strict_encode64(source))
    response = lucee_http('fixed-context-execute', '/lucee/' + filename)
    expect(response.code).to eq('200')
    expect(response.body.strip).to eq('lucee-fixed-context-write')
    remove_file(path)
    @rc[:fixed_writes] << { path: path, source_base64: Base64.strict_encode64(source), positive: positive, interpreted: true, denied: [] }
    [
      ['check', { 'file' => 'module_target_lucee_check' }, {}],
      ['base', { 'file' => '/.' }, { 'imgSrc' => '' }],
      ['write', { 'file' => '/../../../context/' + filename }, { 'imgSrc' => source }]
    ].each do |label, query, form|
      response = lucee_http('fixed-image-' + label, '/lucee/admin/imgProcess.cfm?' + URI.encode_www_form(query), form)
      denied = file(path)
      @rc[:fixed_writes].last[:denied] << { operation: label, code: response.code.to_i, proof: denied }
      rc_save
      # All three are empty 404 responses in the independently captured native
      # 5.3.7.47 pilot; the same context has just served real executable CFML.
      expect(response.code).to eq('404')
      expect(response.body).to eq('')
      expect(denied).to eq('exists' => false)
    end
    _, status = rc_command('fixed-image-directory-absent', 'target', 'test', '-e', '/opt/lucee/web/temp/admin-ext-thumbnails/__/', required: false)
    expect(status).to eq(1)
  ensure
    primary = $ERROR_INFO
    begin
      remove_file(path) if path
      remove_image_directory
    rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
      (@rc[:cleanup_errors] ||= []) << { type: e.class.name, message: e.message }
      raise unless primary
    ensure
      rc_save
    end
  end

  def fixed_owner
    content = "Lucee fixed 'single' \"double\" \\ $HOME ${literal} $(printf nested) #hash 雪😀\r\nNext\tend\n"
    2.times do |iteration|
      path = "/tmp/module-target-lucee-fixed-owner-#{Process.pid}-#{iteration}"
      command = 'printf %s ' + Shellwords.escape(content) + ' >> ' + path
      native_control(command, path, content)
      native_fixed_write
      console_command('back') if iteration.zero?
      console_command('use ' + laravel_owner) if iteration.zero?
      rc_json("begin;active_module.datastore['CMD']=#{command.inspect};true;end")
      offset = rc_json('framework.instance_variable_get(:@lucee_events).length')
      options = { 'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'AutoCheck' => true, 'ForceExploit' => false, 'AllowNoCleanup' => true, 'DisablePayloadHandler' => true, 'WfsDelay' => 0, 'HttpClientTimeout' => 15 }
      output = run_target_module(laravel_owner, 'target', options, action: 'run -z', reuse_module: true, allow_errors: true)
      selection = rc_json('active_module.object_id')
      expect(selection).to eq(@selected_fixed_owner) if iteration.positive?
      @selected_fixed_owner = selection
      events = rc_json("framework.instance_variable_get(:@lucee_events).drop(#{offset})")
      denied = file(path)
      @rc[:calls] << { kind: 'fixed-owner', iteration: iteration, command_base64: Base64.strict_encode64(command.b), options: options, selection: selection, output: output, events: events, denied: denied }
      rc_save
      expect(events.filter_map { |row| row['check'] }).to eq([{ 'code' => 'safe', 'reason' => 'The target is not vulnerable' }])
      expect(events.select { |row| %w[write_cfml_stub execute_command].include?(row['method']) }).to eq([])
      expect(events.select { |row| row['event'] == 'call' && row['method'] == 'exploit' && row['source'].end_with?('/modules/exploits/linux/http/lucee_admin_imgprocess_file_write.rb') }).to eq([])
      expect(events.select { |row| row['request'] }.map { |row| row['request'].fetch('uri') }).to eq(['/lucee/admin/imgProcess.cfm'])
      expect(output).to include('The target is not vulnerable')
      expect(denied).to eq('exists' => false)
    ensure
      remove_file(path) if path
      rc_save
    end
  end
end
