# frozen_string_literal: true

require_relative '../rsync_creds/native'

# Native osTicket controls and actual console entry points with exact loot proof.
module OsticketTarget
  include RsyncCredentialTarget

  OWNER = 'auxiliary/gather/osticket_arbitrary_file_read'
  PASSWORD = 'Module-target-password42!'
  CLIENT = 'module-client@example.test'

  def rc_owner
    OWNER
  end

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'osticket.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    %w[app db reporting_db]
  end

  def ot_runtime
    endpoint = target_endpoint('app')
    {
      compose: target_runtime.fetch('compose'), authority: "#{endpoint.fetch('host')}:#{endpoint.fetch('port')}",
      base: "http://#{endpoint.fetch('host')}:#{endpoint.fetch('port')}#{ENV.fetch('OSTICKET_PREFIX', '')}",
      release: ENV.fetch('OSTICKET_RELEASE'), password: PASSWORD, client_email: CLIENT,
      poc_path: File.expand_path('tmp/module-target-osticket-sources/osticket_ticket_payload_gen.py')
    }
  end

  def ot_control(action, values = {})
    argv = target_runtime.fetch('compose') + ['exec', '-T', '--user', '33', 'app', 'php', '/opt/module-target/control.php']
    output, error, status = Open3.capture3(*argv, stdin_data: JSON.generate(ot_runtime.merge(action: action).merge(values)))
    @rc.fetch(:commands) << { action: action, argv: argv, exit: status.exitstatus, stdout_base64: Base64.strict_encode64(output.b), stderr: error }
    rc_save
    expect(status.success?).to be(true), error + output
    JSON.parse(output)
  end

  def ot_native(phase)
    directory = File.join(target_runtime.fetch('artifacts'), 'native-' + phase)
    FileUtils.mkdir_p(directory)
    path = File.join(directory, 'runtime.json')
    File.write(path, JSON.pretty_generate(ot_runtime.merge(directory: directory, phase: phase)))
    output, error, status = Open3.capture3('python3', 'test/module_targets/osticket/native_control.py', path)
    File.write(File.join(directory, 'process.stdout'), output)
    File.write(File.join(directory, 'process.stderr'), error)
    expect(status.success?).to be(true), output + error
    proof = JSON.parse(File.read(File.join(directory, 'native-proof.json')))
    expect(proof.fetch('passed')).to be(true)
    @rc.fetch(:native) << proof
    rc_resources(phase)
    rc_save
  end

  def ot_call(label, options = {}, action: 'run', reuse: false)
    record = { label: label, options: options, action: action }
    @rc.fetch(:calls) << record
    selected = {
      'TARGETURI' => ENV.fetch('OSTICKET_PREFIX', '') + '/', 'USERNAME' => CLIENT, 'PASSWORD' => PASSWORD,
      'LOGIN_PORTAL' => 'client', 'AutoCheck' => true, 'HttpClientTimeout' => 5,
      'SCP_TICKET_EMAIL' => CLIENT, 'SCP_TICKET_NAME' => 'Module Target Client', 'TICKET_SUBJECT' => 'MCV osTicket case'
    }.merge(options)
    run_target_module(OWNER, 'app', selected, action: action, allow_errors: true, reuse_module: reuse, command_timeout: 90) do |output|
      record[:output_base64] = Base64.strict_encode64(output.b)
      record[:identity] = rc_json('{object_id:active_module.object_id,config:Msf::Config.config_directory}')
      rc_save
    end
  end

  def ot_loot_files
    rc_json('Dir[File.join(Msf::Config.loot_directory,"*")].select{|p|File.file?(p)}')
  end

  def ot_read(label, file, encoding: 'b64', portal: 'client', create: false, reuse: false, options: {})
    selected = { 'FILE' => file + ':' + encoding, 'LOGIN_PORTAL' => portal }
    selected['USERNAME'] = 'module_admin' if portal == 'scp'
    selected['TICKET_NUMBER'] = @ticket.fetch('ticket_number') unless create
    selected.merge!('AutoCheck' => false) if reuse
    before = ot_loot_files
    output = ot_call(label, selected.merge(options), reuse: reuse)
    paths = ot_loot_files - before
    actual = paths.map { |path| File.binread(path) }
    @rc.fetch(:loot) << { label: label, paths: paths, sha256: actual.map { |bytes| Digest::SHA256.hexdigest(bytes) } }
    rc_save
    [output, actual]
  end

  def ot_recover_tickets
    current = ot_control('state').fetch('tickets')
    ids = current.map { |ticket| ticket.fetch('ticket_id') } - @ticket_baseline.map { |ticket| ticket.fetch('ticket_id') }
    ot_control('delete', ids: ids) unless ids.empty?
    expect(ot_control('state').fetch('tickets')).to eq(@ticket_baseline)
  end
end
