# frozen_string_literal: true

require 'json'
require 'net/http'
require 'open3'
require 'rexml/document'

# Independent policy and data checks against genuine Joomla installations.
class NativeJoomlaProbe
  def initialize
    @runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
    @definitions = JSON.parse(File.read(File.join(__dir__, 'profiles.json')))
    @accounts = JSON.parse(File.read(File.join(__dir__, 'accounts.json')))
    @requests = []
    @commands = []
  end

  def run
    profiles = @definitions.fetch('profiles').to_h do |service, definition|
      before = inspect_target(service)
      verify_identity(before, definition)
      base = definition.fetch('prefix')
      homepage = request(service, "#{base}/")
      raise "Not genuine Joomla HTML: #{service}" unless homepage.fetch(:code) == 200 && homepage.fetch(:body).match?(/<meta name="generator" content="Joomla!/i)

      version_paths = %w[administrator/manifests/files/joomla.xml language/en-GB/en-GB.xml templates/system/css/system.css media/system/js/mootools-more.js language/en-GB/en-GB.ini htaccess.txt language/en-GB/en-GB.com_media.ini]
      versions = version_paths.to_h { |path| [path, request(service, "#{base}/#{path}")] }
      if definition.fetch('version_visible')
        xml = versions.fetch('administrator/manifests/files/joomla.xml')
        raise 'Native version manifest unavailable' unless xml.fetch(:code) == 200
        raise 'Native version manifest mismatch' unless REXML::Document.new(xml.fetch(:body)).elements['extension/version'].text == definition.fetch('version')
      else
        raise 'Version hardening not enforced' unless versions.values.all? { |response| response.fetch(:code) == 403 }
      end

      routes = %w[users config/application].to_h do |path|
        endpoint = "#{base}/api/index.php/v1/#{path}"
        ordinary = request(service, endpoint)
        admin = request(service, endpoint, user: 'module_admin')
        wrong = request(service, endpoint, user: 'module_admin', password: 'module-target-wrong-password')
        limited = request(service, endpoint, user: 'module_reader')
        raise 'API access policy mismatch' unless [ordinary[:code], admin[:code], wrong[:code], limited[:code]] == [401, 200, 401, 401]

        [path, { ordinary: ordinary, admin: admin, wrong: wrong, limited: limited }]
      end
      empty = request(service, "#{base}/api/index.php/v1/users?filter%5Bsearch%5D=module-target-absent-user", user: 'module_admin')
      raise 'Native filtered empty user list mismatch' unless empty.fetch(:code) == 200 && JSON.parse(empty.fetch(:body)).fetch('data') == []

      after = inspect_target(service)
      verify_identity(after, definition)
      bypass = %w[users config/application].to_h do |path|
        response = request(service, "#{base}/api/index.php/v1/#{path}?public=true")
        expected_code = definition.fetch('vulnerable') ? 200 : 401
        raise "Native public access mismatch: #{service} #{path}" unless response.fetch(:code) == expected_code

        [path, response]
      end
      if definition.fetch('vulnerable')
        verify_users(JSON.parse(bypass.fetch('users').fetch(:body)), after)
        verify_config(JSON.parse(bypass.fetch('config/application').fetch(:body)), after)
      end
      [service, { native_before: before, native_after: after, homepage: homepage, versions: versions, routes: routes, empty_users: empty, bypass: bypass }]
    end
    unrelated = request('unrelated', '/')
    raise 'Unrelated HTTP identity mismatch' unless unrelated.fetch(:code) == 200 && unrelated.fetch(:body).include?('module-target-http-marker')

    unrelated_api = request('unrelated', '/api/index.php/v1/users?public=true')
    raise 'Unrelated API control mismatch' unless unrelated_api.fetch(:code) == 404

    { profiles: profiles, unrelated: unrelated, unrelated_api: unrelated_api, requests: @requests.size, commands: @commands }
  end

  private

  def request(service, path, user: nil, password: nil)
    endpoint = @runtime.fetch('endpoints').fetch(service)
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 10
    request = Net::HTTP::Get.new(path)
    request['Host'] = @definitions.fetch('vhost')
    request['Accept'] = '*/*'
    request.basic_auth(user, password || @accounts.fetch(user).fetch('password')) if user
    response = http.request(request)
    record = { service: service, path: path, user: user, code: response.code.to_i, headers: response.to_hash, body: response.body }
    @requests << record
    record
  end

  def inspect_target(service)
    arguments = @runtime.fetch('compose') + ['exec', '-T', service, 'php', '/opt/module-target/inspect.php']
    stdout, stderr, status = Open3.capture3(*arguments)
    @commands << { service: service, argv: arguments, exitstatus: status.exitstatus, stderr: stderr, stdout: stdout }
    raise "Native Joomla inspection failed: #{service}: #{stderr}" unless status.success? && stderr.empty?

    JSON.parse(stdout)
  end

  def verify_identity(native, definition)
    raise 'Native version mismatch' unless native.fetch('version') == definition.fetch('version') && native.fetch('php') == '8.1.16'
    raise 'Native reviewed router mismatch' unless native.fetch('router_sha256') == definition.fetch('router_sha256')
    raise 'Native users/passwords mismatch' unless native.fetch('users').map { |user| user.fetch('username') }.sort == @accounts.keys.sort && native.fetch('users').all? { |user| user.fetch('password_valid') }

    @accounts.each do |name, account|
      user = native.fetch('users').find { |row| row.fetch('username') == name }
      raise 'Native account data mismatch' unless user.values_at('id', 'name', 'email') == account.values_at('id', 'name', 'email')
    end
    raise 'Native DB fixture identity mismatch' unless native.fetch('configuration').values_at('host', 'user', 'password', 'dbprefix') == %w[db module_target module-target-db-password jt_]

    %w[users config].each do |element|
      plugin = native.fetch('plugins').find { |row| row.fetch('folder') == 'webservices' && row.fetch('element') == element }
      raise "Native webservice disabled: #{element}" unless plugin.fetch('enabled') == 1
    end
  end

  def verify_users(document, native)
    users = document.fetch('data')
    raise 'Native exposed user count mismatch' unless users.size == native.fetch('users').size

    native.fetch('users').each do |user|
      exposed = users.find { |entry| entry.fetch('attributes').fetch('username') == user.fetch('username') }.fetch('attributes')
      fields = %w[id name username email block sendEmail registerDate lastvisitDate]
      raise 'Native exposed user attributes mismatch' unless exposed.values_at(*fields) == user.values_at(*fields)
      raise 'Native exposed group mismatch' unless exposed.fetch('group_names') == user.fetch('group_name')
    end
  end

  def verify_config(document, native)
    exposed = document.fetch('data').each_with_object({}) { |entry, result| result.merge!(entry.fetch('attributes').except('id')) }
    %w[host user password db dbtype dbprefix dbencryption].each do |field|
      raise "Native exposed config mismatch: #{field}" unless exposed.fetch(field) == native.fetch('configuration').fetch(field)
    end
    raise 'Native API unexpectedly exposed its excluded site secret' if exposed.key?('secret')
  end
end

puts JSON.pretty_generate(NativeJoomlaProbe.new.run)
