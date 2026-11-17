# frozen_string_literal: true

require 'nokogiri'
require 'rex/mime/message'
require_relative '../wp_batch_desync_rce/native'

# Native vendor controls do not call the owner or its WordPress helpers.
module HashFormNative
  include WordpressBatchChainTarget

  def chain_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-hash-form.json'), JSON.pretty_generate(@chain)) if @chain
  end

  def chain_identity(label, *)
    output, = chain_command(label, 'app', 'php', '/opt/module-target/control.php', *)
    data = JSON.parse(output)
    (@chain[:identities] ||= []) << { label: label, data: data }
    chain_save
    expect(data.values_at('core', 'php', 'uid', 'selected_release', 'database', 'role')).to eq(['6.8.3', '8.3.28', 33, @release, 'wp_root', 'module_target@%'])
    expect(data.values_at('version', 'constant_version', 'active_plugins')).to eq([@release, @release, ['hash-form/hash-form.php']])
    expect(data.values_at('machine', 'curl', 'bash', 'server_mode')).to eq(['x86_64', true, true, @server_mode])
    expect(data.fetch('server')).to start_with('11.2.2-MariaDB')
    expect(data.fetch('grants').join("\n")).not_to include('ALL PRIVILEGES ON *.*', 'GRANT OPTION')
    expect(data.values_at('db_error', 'bootstrap_output_base64', 'table_errors')).to eq(['', '', []])
    expect(data.fetch('archive_sha256')).to eq(@catalog.fetch('sha256'))
    expect(data.fetch('installed_sha256')).to eq(@catalog.fetch('installed_sha256'))
    expect(data.values_at('home', 'siteurl')).to eq(['http://module-target.test' + @prefix] * 2)
    expect(data.fetch('filesystem').values_at('writable', 'upload_error')).to eq([true, false])
    expect(data.fetch('filesystem').fetch('free_bytes')).to be > 16_777_216
    expect(data.fetch('tables').fetch('forms').map { |form| form.values_at('id', 'status') }).to eq([['1', 'published']])
    expect(data.fetch('tables').fetch('fields').map { |field| field.fetch('type') }).to eq(['upload'])
    expect(data.fetch('tables').values_at('entries', 'entry_meta')).to eq([[], []])
    data
  end

  def hash_selected(data)
    data.except('filesystem', 'bootstrap_output_base64', 'operation_result')
  end

  def chain_assert_restored(current, original = @baseline)
    expect(hash_selected(current)).to eq(hash_selected(original))
  end

  def hash_frontend(label, data)
    response = chain_request(label, data.fetch('preview'))
    expect(response.code).to eq('200')
    html = Nokogiri::HTML(response.body)
    script = html.at_css('script#frontend-js-extra')&.text.to_s
    json = script[/var\s+hashform_vars\s*=\s*(\{[^\r\n]+\})\s*;/, 1]
    expect(json).not_to be_nil
    values = JSON.parse(json)
    expect(values.fetch('ajax_nounce')).to match(/\A[a-f0-9]{10}\z/)
    expect(URI(values.fetch('ajaxurl')).path).to eq(@prefix + '/wp-admin/admin-ajax.php')
    upload = html.css('div[data-extensions]')
    expect(upload.length).to eq(1)
    extensions = upload.first['data-extensions'].split(',')
    expect(extensions).to include('gif')
    expect(extensions).not_to include('php')
    { nonce: values.fetch('ajax_nounce'), ajax: URI(values.fetch('ajaxurl')).path, extensions: extensions }
  end

  def hash_upload(label, name, bytes, fields, allowed: fields.fetch(:extensions), nonce: :valid, limit: 1_048_576, multipart: false)
    query = [['action', 'hashform_file_upload_action'], ['sizeLimit', limit.to_s]]
    query << ['file_uploader_nonce', nonce == :valid ? fields.fetch(:nonce) : 'wrong-native-nonce'] unless nonce == :missing
    allowed.each_with_index { |extension, index| query << ["allowedExtensions[#{index}]", extension] }
    if multipart
      body = Rex::MIME::Message.new
      body.add_part(bytes, 'image/gif', 'binary', 'form-data; name="qqfile"; filename="' + name + '"')
      content_type = 'multipart/form-data; boundary=' + body.bound
      body = body.to_s
    else
      query << ['qqfile', name]
      body = bytes
      content_type = 'application/octet-stream'
    end
    chain_request(label, fields.fetch(:ajax) + '?' + URI.encode_www_form(query), body, raw: true, headers: { 'Content-Type' => content_type })
  end

  def hash_get(label, name)
    chain_request(label, @prefix + '/wp-content/uploads/hashform/temp/' + name)
  end

  def hash_delete(label, name, fields, token, wrong: false)
    response = chain_request(label, fields.fetch(:ajax), { 'action' => 'hashform_file_delete_action', '_wpnonce' => wrong ? 'wrong-native-nonce' : fields.fetch(:nonce), 'path' => token }, form: true)
    expect([response.code, response.body.strip]).to eq(['200', wrong ? 'error' : 'success'])
    expect(hash_get(label + '-state', name).code).to eq(wrong ? '200' : '404')
  end

  def hash_uploaded(response, name)
    expect(response.code).to eq('200')
    data = JSON.parse(response.body)
    expect(data.fetch('success')).to be(true)
    expect(URI(data.fetch('url')).path).to eq(@prefix + '/wp-content/uploads/hashform/temp/' + name)
    expect(data.fetch('path')).to be_a(String)
    expect(data.fetch('path')).not_to be_empty
    data
  end

  def hash_ordinary(label, fields, multipart: false)
    name = 'native-hash-control.gif'
    bytes = Base64.strict_decode64('R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==')
    data = hash_uploaded(hash_upload(label + '-upload', name, bytes, fields, multipart: multipart), name)
    expect(hash_get(label + '-bytes', name).body.b).to eq(bytes.b)
    hash_delete(label + '-wrong-delete', name, fields, data.fetch('path'), wrong: true)
    hash_delete(label + '-delete', name, fields, data.fetch('path'))
  end

  def hash_fetch_route(phase, callback)
    server = TCPServer.new(callback.fetch(:bind), 0)
    port = server.local_address.ip_port
    path = "/native-hash-fetch-#{Process.pid}-#{phase}"
    body = 'Owned native Hash Form fetch control'
    worker = Thread.new do
      raise Timeout::Error, 'Native fetch request did not arrive' unless IO.select([server], nil, nil, 12)

      socket = server.accept
      begin
        request = +''
        until request.include?("\r\n\r\n")
          raise Timeout::Error, 'Native fetch headers did not arrive' unless IO.select([socket], nil, nil, 5)

          request << socket.readpartial(4096)
          raise 'Native fetch request exceeded header limit' if request.bytesize > 16_384
        end
        raise 'Native fetch path differs' unless request.lines.first == "GET #{path} HTTP/1.1\r\n"

        socket.write("HTTP/1.1 200 OK\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n" + body)
        request
      ensure
        socket.close
      end
    end
    worker.report_on_exception = false
    output, = chain_command(phase + '-native-http-fetch', 'app', '/usr/bin/curl', '--fail', '--silent', '--show-error', '--max-time', '10', "http://#{callback.fetch(:host)}:#{port}#{path}")
    expect(output).to eq(body)
    worker.join(12)
    expect(worker.alive?).to be(false)
    (@chain[:fetch_controls] ||= []) << { phase: phase, host: callback.fetch(:host), bind: callback.fetch(:bind), port: port, request: worker.value, exact_bytes: true }
    chain_save
  ensure
    server&.close
    worker&.kill if worker&.alive?
    worker&.join
  end

  def chain_native_gate(phase)
    boot = chain_identity(phase + '-boot')
    expect(boot.fetch('users').length).to eq(4)
    expect(boot.fetch('users').map { |user| user.fetch('sessions') }).to all(eq([]))
    fields = hash_frontend(phase + '-real-preview', boot)
    hash_ordinary(phase + '-ordinary-xhr', fields)
    original = chain_identity(phase + '-baseline')
    expect(original.fetch('filesystem').values_at('exists', 'uid')).to eq([true, 33])
    (@chain[:initialization] ||= []) << { phase: phase, changed: hash_selected(boot).keys.reject { |key| hash_selected(boot)[key] == hash_selected(original)[key] } }
    if %w[1.1.6 1.1.9].include?(@release)
      response = hash_upload(phase + '-multipart-unsupported', 'native-hash-fallback.gif', 'Owned bytes', fields, multipart: true)
      expect(JSON.parse(response.body).fetch('error')).to eq('No files were uploaded.')
      expect(hash_get(phase + '-multipart-absent', 'native-hash-fallback.gif').code).to eq('404')
    else
      hash_ordinary(phase + '-ordinary-multipart', fields, multipart: true)
    end
    %i[missing wrong].each do |nonce|
      name = 'native-hash-' + nonce.to_s + '.gif'
      response = hash_upload(phase + '-' + nonce.to_s + '-nonce', name, 'Owned bytes', fields, nonce: nonce)
      expect(response.body).not_to include('"success":true')
      expect(hash_get(phase + '-' + nonce.to_s + '-absent', name).code).to eq('404')
    end
    name = 'native-hash-outside.txt'
    response = hash_upload(phase + '-extension-mismatch', name, 'Owned text', fields)
    if %w[1.1.6 1.1.9].include?(@release)
      data = hash_uploaded(response, name)
      expect(hash_get(phase + '-known-txt-gap', name).body).to eq('Owned text')
      hash_delete(phase + '-known-txt-gap-delete', name, fields, data.fetch('path'))
    else
      expect(JSON.parse(response.body).fetch('error')).to include('invalid extension')
      expect(hash_get(phase + '-extension-absent', name).code).to eq('404')
    end
    response = hash_upload(phase + '-size-limit', 'native-hash-large.gif', 'Owned too-large bytes', fields, limit: 8)
    expect(JSON.parse(response.body).fetch('error')).to eq('File is too large')
    expect(hash_get(phase + '-size-absent', 'native-hash-large.gif').code).to eq('404')
    chain_assert_restored(chain_identity(phase + '-negatives-restored'), original)
    name = 'nativehf.php'
    proof = File.binread(File.join(__dir__, 'proof.php'))
    response = hash_upload(phase + '-php-upload', name, proof, fields, allowed: ['php'])
    if %w[execute source].include?(@php_mode)
      hash_uploaded(response, name)
      executed = hash_get(phase + '-php-result', name)
      expect(executed.code).to eq('200')
      if @php_mode == 'source'
        expect(executed.body.b).to eq(proof.b)
        expect(executed['Server']).to start_with('Apache/')
        (@chain[:native_source_guards] ||= []) << { phase: phase, name: name, sha256: Digest::SHA256.hexdigest(executed.body), server: executed['Server'], literal_source: true }
      else
        result = JSON.parse(executed.body)
        expect(result.values_at('marker', 'uid', 'bash')).to eq(['MODULE_TARGET_NATIVE_HASH_PROOF', 33, true])
        expect(result.fetch('shell')).to start_with('uid=33(')
        expect(result.fetch('sapi')).to eq(@server_mode == 'phpdev' ? 'cli-server' : 'apache2handler')
        (@chain[:native_execution] ||= []) << { phase: phase, **result }
      end
      inspected = chain_identity(phase + '-owned-inspection', 'inspect-owned', name, Digest::SHA256.hexdigest(proof)).fetch('operation_result')
      expect(Base64.strict_decode64(inspected.fetch('source_base64'))).to eq(proof)
      hash_delete(phase + '-proof-delete', name, fields, inspected.fetch('path'))
    else
      expect(response.code).to eq('500')
      expect(hash_get(phase + '-php-absent', name).code).to eq('404')
      expect(response.body).not_to include('"success":true')
    end
    hash_ordinary(phase + '-post-boundary-ordinary', fields)
    final = chain_identity(phase + '-restored')
    chain_assert_restored(final, original)
    callback = chain_callback_probe
    hash_fetch_route(phase, callback)
    chain_resources(phase, %w[app db reporting_db])
    @chain.fetch(:controls) << { phase: phase, php_execution_allowed: @php_mode == 'execute', php_mode: @php_mode, server_mode: @server_mode, multipart_supported: !%w[1.1.6 1.1.9].include?(@release), txt_gap: %w[1.1.6 1.1.9].include?(@release), selected_state_restored: true, passed: true }
    chain_save
    [final, callback, fields]
  end
end
