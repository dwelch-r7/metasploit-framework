# frozen_string_literal: true

require_relative '../irssi_creds/native'

# Preserve genuine session, exact raw-loot and recovery controls from Irssi.
module IrssiNickservTarget
  include IrssiCredentialTarget

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'irssi-nickserv-credentials.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def nc_action(action)
    output, = rc_command(action + '-nickserv', 'linux', 'python3', '/opt/irssi-fixture-native.py', action)
    data = JSON.parse(output)
    @rc[action.to_sym] = data
    rc_save
    expect(data.fetch('native_passed')).to be(true)
    data
  end

  def rc_native(phase)
    output, = rc_command(phase + '-native', 'linux', 'python3', '/opt/irssi-native.py', phase)
    data = JSON.parse(output)
    @rc.fetch(:native) << { phase: phase, data: data }
    rc_save
    expect(data.values_at('native_passed', 'hostname', 'uid')).to eq([true, 'module-target-irssi-nickserv', 0])
    data
  end

  def nc_verify(call)
    ic_verify(call)
    expected = call.fetch(:fixture).fetch('expected_passwords')
    return if expected.empty?

    output = Base64.strict_decode64(call.fetch(:output_base64))
    # Services differ in argument order: preserve the real wire arguments
    # without labelling an account name as a password.
    wire = call.fetch(:fixture).fetch('native_client').fetch('wire')
    arguments = wire[/^<< PRIVMSG nickserv :identify ([^\r\n]+)$/i, 1]
    if arguments && arguments.split.length > 1
      found = output.match(/Found NickServ IDENTIFY authentication data of (.*?) in irssi config at #{Regexp.escape(call.fetch(:fixture).fetch('path'))}/)
      expect(found).not_to be_nil
      expect(found[1]).to eq(arguments)
      expect(output).not_to include('Found IRC password(s) of ')
      return
    end

    found = output.match(/Found IRC password\(s\) of (.*?) in irssi config at #{Regexp.escape(call.fetch(:fixture).fetch('path'))}/)
    expect(found).not_to be_nil
    expect(found[1].split(',')).to eq(expected)
  end
end
