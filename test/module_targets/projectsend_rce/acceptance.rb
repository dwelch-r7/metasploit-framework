# frozen_string_literal: true

require_relative '../projectsend/acceptance'

# Native producer/API gates precede original owning delivery and state checks.
module ProjectsendRceTarget
  include ProjectsendTarget

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'projectsend-rce-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def pr_native(action, *arguments)
    argv = ['python3', '-B', 'test/module_targets/projectsend_rce/native_probe.py', action, *arguments]
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { action: action, argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def pr_ready
    @rc[:readiness] = ps_native('before')
    expect(@rc.fetch(:readiness)).to include('passed' => true, 'version' => 'r1605', 'module_invoked' => false)
    @rc[:mail_containment] = pr_native('contain-mail')
    @rc[:readiness]['baseline'] = @rc.fetch(:mail_containment).fetch('baseline')
    rc_resources('before')
    @rc[:observer] = rc_json("begin;load 'test/module_targets/projectsend_rce/observe.rb';ProjectsendRceObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    @rc[:calibrated] = true
    @rc[:cases] = [
      { label: 'plain', marker: 'projectsend-command', command: 'printf %s projectsend-command' },
      { label: 'quoted-unicode-crlf', marker: "ProjectSend \"quoted\" & snow 雪\r\n", command: "printf '%s\\r\\n' 'ProjectSend \"quoted\" & snow 雪'" }
    ].map do |entry|
      proof = "/tmp/module-target-projectsend-rce-#{Process.pid}-#{entry.fetch(:label)}"
      entry.merge(proof: proof, command: entry.fetch(:command) + ' > ' + proof)
    end
    @rc.fetch(:cases).each do |entry|
      stock = rc_json("begin;p=framework.payloads.create('php/exec');p.datastore['CMD']=#{entry.fetch(:command).inspect};{program_base64:Base64.strict_encode64(p.generate.b),source:p.method(:generate).source_location};end")
      expect(File.realpath(stock.fetch('source').first)).to eq(File.realpath('modules/payloads/singles/php/exec.rb'))
      control = File.join(target_runtime.fetch('artifacts'), entry.fetch(:label) + '-control.json')
      File.write(control, JSON.pretty_generate(stock.merge('proof' => entry.fetch(:proof), 'marker_base64' => Base64.strict_encode64(entry.fetch(:marker).b))))
      entry[:native] = pr_native('control', control)
      expect(entry.fetch(:native)).to include('module_invoked' => false, 'stock_cli_passed' => true, 'exact_upload_and_web_proof' => true, 'portal_row_removed' => true, 'fixture_options_restored' => true)
    end
    @rc[:before_owner] = pr_native('state')
    expect(@rc.fetch(:before_owner).fetch('options')).to eq(@rc.fetch(:readiness).fetch('baseline'))
    @rc[:payloads_calibrated] = true
    rc_save
  end

  def pr_execute
    @rc.fetch(:cases).each_with_index do |entry, index|
      offset = rc_json('framework.instance_variable_get(:@projectsend_rce_events).length')
      call = { label: entry.fetch(:label), options: { 'SSL' => false, 'TARGET' => 0, 'PAYLOAD' => 'php/exec', 'CMD' => entry.fetch(:command), 'AutoCheck' => index.zero?, 'DisablePayloadHandler' => true, 'WfsDelay' => 0 } }
      @rc[:calls] << call
      run_target_module(OWNER, 'target', call.fetch(:options), reuse_module: index.positive?, allow_errors: true, command_timeout: 100) do |output|
        call[:output] = output
        call[:selection] = rc_json('active_module.object_id')
        call[:events] = rc_json("framework.instance_variable_get(:@projectsend_rce_events).drop(#{offset})")
        call[:proof] = pr_native('proof', entry.fetch(:proof))
        call[:actual_state] = pr_native('state')
        rc_save
      end
      call[:marker_removed] = pr_native('proof', entry.fetch(:proof), 'remove')
      rc_save
    end
    @rc[:owner_attempted] = true
    @rc.fetch(:calls).zip(@rc.fetch(:cases)).each_with_index do |(call, entry), index|
      expect(call.fetch(:selection)).to eq(@rc.fetch(:calls).first.fetch(:selection))
      expect(call.fetch(:proof)).to eq('exists' => true, 'uid' => 1000, 'base64' => Base64.strict_encode64(entry.fetch(:marker).b))
      expect(call.fetch(:marker_removed)).to eq('exists' => false)
      original = call.fetch(:events).select { |row| row['event'] == 'call' && row['method'] == 'exploit' && File.realpath(row.fetch('source')) == File.realpath('modules/exploits/linux/http/projectsend_unauth_rce.rb') }
      expect(original.length).to eq(1)
      checks = call.fetch(:events).filter_map { |row| row['check'] }
      expect(checks).to eq(index.zero? ? [{ 'code' => 'appears', 'reason' => 'The target appears to be vulnerable' }] : [])
      expect(call.fetch(:events).filter_map { |row| row['payload'] }).to eq([{ 'name' => 'php/exec', 'command' => entry.fetch(:command) }])
      expect(call.fetch(:events).filter_map { |row| row['program_base64'] }.length).to eq(1)
      expect(call.fetch(:actual_state).fetch('files')).to eq(@rc.fetch(:before_owner).fetch('files'))
      expect(call.fetch(:actual_state).fetch('physical_uploads')).to eq(@rc.fetch(:before_owner).fetch('physical_uploads'))
      existing = @rc.fetch(:before_owner).fetch('users')
      users = call.fetch(:actual_state).fetch('users')
      expect(users.select { |user| existing.any? { |original_user| original_user.fetch('id') == user.fetch('id') } }).to eq(existing)
      created = users - existing
      expect(created.length).to eq(index + 1)
      expect(created.all? { |user| user.fetch('active').to_i == 1 && user.fetch('level').to_i.zero? }).to be(true)
      expect(call.fetch(:output)).not_to include('Exploit failed', 'Error while running command')
    end
  end

  def pr_preservation
    expect(@rc[:owner_attempted]).to be(true)
    @rc[:after_owner] = pr_native('state')
    baseline = @rc.fetch(:before_owner).fetch('options').to_h { |row| [row.fetch('name'), row] }
    @rc[:option_changes] = @rc.fetch(:calls).to_h do |call|
      actual = call.fetch(:actual_state).fetch('options').to_h { |row| [row.fetch('name'), row] }
      changes = (baseline.keys | actual.keys).sort.filter_map do |name|
        { name: name, before: baseline[name], after: actual[name] } unless baseline[name] == actual[name]
      end
      [call.fetch(:label), changes]
    end
    rc_save
    expect(@rc.fetch(:option_changes).values).to eq([[], []])
  end

  def pr_cleanup
    return unless @rc[:readiness]

    @rc[:before_fixture_recovery] = pr_native('state')
    rc_resources('after')
    @rc[:fixture_baseline_restored] = ps_native('restore-baseline')
    @rc[:factory_restored] = ps_native('after')
    expect(@rc.fetch(:factory_restored)).to include('preserved' => true, 'restored' => true)
  ensure
    rc_save
  end
end
