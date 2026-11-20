# frozen_string_literal: true

require 'http/cookie'
require_relative '../laravel/commands'

# Cookie-session transport and release checks for the genuine InvoiceShelf app.
module InvoiceShelfTarget
  include LaravelCommandTarget

  def laravel_component
    'invoiceshelf'
  end

  def laravel_owner
    InvoiceShelfObservation::OWNER
  end

  def laravel_uid
    33
  end

  def native_command(command, path, content)
    expect(file(path)).to include('exists' => false)
    uri = URI::HTTP.build(host: target_endpoint('target').fetch('host'), port: target_endpoint('target').fetch('port'), path: '/login')
    # Parse against the declared cookie origin while HTTP stays on the lab endpoint.
    uri = URI(ENV.fetch('INVOICESHELF_COOKIE_ORIGIN', uri.to_s))
    response = http('/login')
    expect(response.code).to eq('200')
    cookies = response.get_fields('set-cookie').flat_map { |header| HTTP::Cookie.parse(header, uri) }.to_h { |cookie| [cookie.name, cookie.value] }
    cookie_name = @native.fetch('cookie')
    session = native('cookie', { name: cookie_name, value: cookies.fetch(cookie_name) }, 'native-session')
    expect(session.fetch('prefix_valid')).to be(true)
    name = session.fetch('value')
    expect(cookies).to have_key(name)
    generated = native('gadget', { name: name, command_base64: Base64.strict_encode64(command.b) }, 'native-gadget')
    expect(file(path)).to include('exists' => false)
    expect(http('/login', 'Cookie' => cookie_name + '=' + cookies.fetch(cookie_name) + '; ' + name + '=' + generated.fetch('value')).code).to eq('200')
    expect(file(path)).to eq('exists' => true, 'uid' => 33, 'base64' => Base64.strict_encode64(content.b))
  ensure
    rc_command('remove-native-proof', 'target', 'rm', '-f', '--', path)
    expect(file(path)).to include('exists' => false)
  end

  def native_verify(label, driver: 'cookie', cookie: 'laravel_session')
    data = native('verify', {}, label)
    expect(data).to include('php' => '8.3.33', 'laravel' => '10.48.16', 'uid' => 33, 'driver' => driver, 'cookie' => cookie, 'serialization' => 'php', 'handler' => 'Illuminate\\Session\\' + (driver == 'file' ? 'FileSessionHandler' : 'CookieSessionHandler'), 'database' => 'sqlite', 'users' => 1, 'companies' => 1, 'invoices' => 0, 'php_supported' => true)
    expect(data.fetch('requirements')).not_to have_key('errors')
    expect(data.fetch('sqlite').fetch('supported')).to be(true)
    expect(data.fetch('source_sha256')).to eq(JSON.parse(File.read('test/module_targets/invoiceshelf/vendor.json')).fetch('source_sha256'))
    data
  end
end
