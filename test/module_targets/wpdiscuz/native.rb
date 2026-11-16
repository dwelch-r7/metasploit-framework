# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'nokogiri'
require 'uri'
require_relative 'profiles'

# Independent requests exercise the installed plugin, without loading the owner.
class WpDiscuzNative
  GIF = Base64.strict_decode64('R0lGODlhAQABAPAAAP///wAAACH5BAAAAAAALAAAAAABAAEAAAICRAEAOw==').freeze
  attr_reader :identity, :baseline

  def initialize(endpoint, profile, execute, record)
    @endpoint = endpoint
    @profile = profile
    @execute = execute
    @record = record
  end

  def snapshot(label)
    value = JSON.parse(@execute.call('snapshot'))
    @record.call('target-snapshots.jsonl', label: label, snapshot: value)
    value
  end

  def recover(ids, label)
    result = JSON.parse(@execute.call('cleanup', ids.join(',')))
    @record.call('operator-recovery.jsonl', label: label, result: result)
    raise 'WordPress attachment recovery differs' unless result.fetch('removed') == ids

    result
  end

  def request(label, path, method: 'GET', body: nil, headers: {}, timeout: 20)
    raise ArgumentError, 'Native request must use a local path' unless path.start_with?('/')

    client = Net::HTTP.new(@endpoint.fetch('host'), @endpoint.fetch('port'), nil)
    client.open_timeout = 5
    client.read_timeout = timeout
    message = method == 'POST' ? Net::HTTP::Post.new(path) : Net::HTTP::Get.new(path)
    message['User-Agent'] = 'ModuleTargetNative/1.0'
    headers.each { |key, value| message[key] = value }
    message.body = body if body
    response = client.request(message)
    @record.call('native-http.jsonl', label: label, method: method, path: path, request_body_base64: body && Base64.strict_encode64(body), request_headers: message.to_hash, code: response.code.to_i, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s))
    response
  end

  def metadata(cookie = nil)
    response = request('comment-form', @identity.fetch('post').fetch('path'), headers: cookie ? { 'Cookie' => cookie } : {})
    raise 'Native comment form did not respond' unless response.code == '200'

    # WordPress emits each localized JSON assignment on a complete line. This
    # independent fixture reader does not use the owner's object scanner.
    line = Nokogiri::HTML(response.body).css('script').flat_map { |script| script.text.lines }.find { |text| text.match?(/\A\s*var wpdiscuzAjaxObj = /) }
    raise 'Native localized comment form is absent' unless line

    text = line.sub(/\A\s*var wpdiscuzAjaxObj = /, '').sub(/;\s*\z/, '')
    document = JSON.parse(text)
    raise 'Native form post differs from actual WordPress post' unless document.fetch('wc_post_id').to_s == @identity.fetch('post').fetch('id').to_s
    raise 'Native nonce is absent' if document.fetch('wmuSecurity').to_s.empty?

    document
  end

  def upload(label, filename, bytes, metadata: self.metadata, nonce: nil, post_id: nil, cookie: nil)
    boundary = '----ModuleTargetWpDiscuzNative7'
    fields = { 'action' => 'wmuUploadFiles', 'wmu_nonce' => nonce || metadata.fetch('wmuSecurity'), 'wmuAttachmentsData' => 'undefined', 'postId' => (post_id || metadata.fetch('wc_post_id')).to_s }
    body = fields.map { |key, value| "--#{boundary}\r\nContent-Disposition: form-data; name=\"#{key}\"\r\n\r\n#{value}\r\n" }.join.b
    body << "--#{boundary}\r\nContent-Disposition: form-data; name=\"wmu_files[0]\"; filename=\"#{filename}\"\r\nContent-Type: image/gif\r\n\r\n".b << bytes.b << "\r\n--#{boundary}--\r\n".b
    headers = { 'Content-Type' => "multipart/form-data; boundary=#{boundary}" }
    headers['Cookie'] = cookie if cookie
    response = request(label, @profile.fetch('prefix') + '/wp-admin/admin-ajax.php', method: 'POST', body: body, headers: headers)
    document = JSON.parse(response.body)
    data = document['data'] if document.is_a?(Hash)
    previews = data['previewsData'] if data.is_a?(Hash)
    images = previews['images'] if previews.is_a?(Hash)
    { 'code' => response.code.to_i, 'document' => document, 'images' => images.is_a?(Array) ? images : [] }
  end

  def upload_path(image)
    uri = URI.parse(image.fetch('url'))
    raise 'Native upload advertised a different endpoint' unless uri.host == @endpoint.fetch('host') && uri.port == @endpoint.fetch('port')

    uri.request_uri
  end

  def accepted_image(result, bytes, label)
    raise 'Native upload was not accepted' unless result.fetch('code') == 200 && result.fetch('document').fetch('success') == true && result.fetch('images').length == 1

    image = result.fetch('images').first
    files = snapshot(label).fetch('attachments')
    raise 'Native attachment identity or bytes differ' unless files.length == 1 && files.first.values_at('id', 'exists', 'size', 'sha256') == [image.fetch('id'), true, bytes.bytesize, Digest::SHA256.hexdigest(bytes)]

    image
  end

  def unrelated_health(label)
    response = request(label, '/')
    raise 'Unrelated HTTP service differs' unless response.code == '200' && response.body.include?('module-target-http-marker')

    current = Digest::SHA256.hexdigest(response.body)
    raise 'Unrelated HTTP response changed' if @unrelated_sha256 && @unrelated_sha256 != current

    @unrelated_sha256 = current
    @record.call('unrelated-health.jsonl', label: label, code: response.code.to_i, body_sha256: current)
  end

  def controls
    if @profile.fetch('mode') == 'unrelated'
      unrelated_health('unrelated-home')

      return
    end

    @identity = snapshot('initial-identity')
    raise 'Native WordPress/PHP/account identity differs' unless @identity.values_at('core', 'php', 'uid') == ['5.2.4', '7.3.11', 33]
    raise 'Native ordinary post setup differs' unless @identity.fetch('post').values_at('type', 'status', 'comments') == %w[post publish open] && @identity.fetch('post').fetch('id') != 1
    raise 'Native upload directory is not writable' unless @identity.fetch('uploads').fetch('writable')
    raise 'Native initial artifacts are not empty' unless @identity.fetch('attachments').empty? && @identity.fetch('owner_proof').nil? && @identity.fetch('native_proof').nil?

    %w[/ /wp-login.php].each do |path|
      response = request('wordpress-health', @profile.fetch('prefix') + path)
      raise 'Native WordPress page failed' unless response.code == '200'
    end
    readme = request('plugin-readme', @profile.fetch('prefix') + '/wp-content/plugins/wpdiscuz/readme.txt')
    if @profile.fetch('mode') == 'absent'
      raise 'Absent plugin was installed' unless readme.code == '404' && @identity.fetch('active') == false && @identity.fetch('active_plugins').empty?

      @baseline = @identity
      return
    end

    release = WpDiscuzProfiles::RELEASES.fetch(@profile.fetch('release'))
    raise 'Installed plugin provenance differs' unless @identity.values_at('version', 'active', 'archive_sha256', 'installed_sha256') == [@profile.fetch('release'), true, release.fetch('sha256'), release.fetch('installed_sha256')]
    raise 'Installed plugin list differs' unless @identity.fetch('active_plugins') == ['wpdiscuz/class.WpdiscuzCore.php']
    raise 'Native readme/version differs' unless readme.code == '200' && readme.body.include?('Stable tag: ' + @profile.fetch('release'))
    raise 'Native guest-upload policy differs' unless [true, 1, '1'].include?(@identity.fetch('guest_upload_enabled')) == (@profile.fetch('mode') != 'guest_disabled')

    @baseline = @identity
    form = metadata
    denied = upload('invalid-nonce', 'module-target-native.gif', GIF, metadata: form, nonce: 'invalid-owned-nonce')
    raise 'Native invalid nonce was accepted' unless denied.fetch('code') == 403 && denied.fetch('images').empty? && snapshot('after-invalid-nonce') == @baseline

    denied = upload('invalid-post', 'module-target-native.gif', GIF, metadata: form, post_id: 1)
    raise 'Native absent post was accepted' unless denied.fetch('images').empty? && snapshot('after-invalid-post') == @baseline

    cookie = nil
    if @profile.fetch('mode') == 'guest_disabled'
      login = URI.encode_www_form('log' => 'module_admin', 'pwd' => 'module-target-password', 'redirect_to' => @profile.fetch('prefix') + '/wp-admin/profile.php')
      response = request('administrator-login', @profile.fetch('prefix') + '/wp-login.php', method: 'POST', body: login, headers: { 'Content-Type' => 'application/x-www-form-urlencoded' })
      cookie = response.get_fields('set-cookie').to_a.map { |value| value.split(';').first }.join('; ')
      raise 'Native administrator authentication failed' unless response.code == '302' && cookie.include?('wordpress_logged_in_')
    end
    result = upload('ordinary-image', 'module-target-native.gif', GIF, metadata: cookie ? metadata(cookie) : form, cookie: cookie)
    image = accepted_image(result, GIF, 'ordinary-image-file')
    response = request('ordinary-image-bytes', upload_path(image))
    raise 'Native ordinary image bytes differ' unless response.code == '200' && response.body.b == GIF

    recover([image.fetch('id')], 'native-image')
    raise 'Native ordinary image cleanup differs' unless snapshot('after-native-image') == @baseline

    %w[GIF8 GIF89a].each do |magic|
      bytes = magic + "<?php file_put_contents('/tmp/module-target-wpdiscuz-native-proof','wpdiscuz_native');echo 'wpdiscuz-native-executed';?>"
      result = upload('php-' + magic, 'module-target-native-' + magic + '.php', bytes, metadata: form)
      accepted = @profile.fetch('mode') == 'affected' && (@profile.fetch('release') != '7.0.0' || magic == 'GIF89a')
      @record.call('native-php-boundaries.jsonl', release: @profile.fetch('release'), magic: magic, expected_accepted: accepted, images: result.fetch('images'), code: result.fetch('code'))
      if accepted
        image = accepted_image(result, bytes, 'native-php-file')
        response = request('native-php-execution', upload_path(image))
        raise 'Native PHP did not execute' unless response.code == '200' && response.body == magic + 'wpdiscuz-native-executed' && snapshot('native-php-proof').fetch('native_proof') == 'wpdiscuz_native'

        recover([image.fetch('id')], 'native-php-' + magic)
      else
        raise 'Native MIME boundary accepted unexpected PHP' unless result.fetch('images').empty?
      end
      raise 'Native PHP cleanup/state differs' unless snapshot('after-native-php-' + magic) == @baseline
    end
  end
end
