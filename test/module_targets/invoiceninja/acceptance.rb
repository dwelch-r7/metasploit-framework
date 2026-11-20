# frozen_string_literal: true

require 'http/cookie'
require_relative '../laravel/commands'

# Route decryption and release checks for the genuine Invoice Ninja app.
module InvoiceNinjaTarget
  include LaravelCommandTarget

  def laravel_component
    'invoiceninja'
  end

  def laravel_owner
    InvoiceNinjaObservation::OWNER
  end

  def laravel_uid
    1500
  end

  def rc_resource_roles
    %w[target database]
  end

  def native_vendor
    JSON.parse(File.read(ENV.fetch('INVOICENINJA_VENDOR', 'test/module_targets/invoiceninja/vendor.json')))
  end

  def native_verify(label)
    data = native('verify', {}, label)
    expect(data).to include('php' => native_vendor.fetch('php'), 'laravel' => native_vendor.fetch('laravel'), 'uid' => laravel_uid, 'database' => 'mysql', 'users' => 1, 'driver' => 'file', 'cookie' => 'invoiceninja_session')
    expect(data.fetch('companies')).to be_positive
    expect(data.fetch('timezones')).to eq(115)
    expect(data.fetch('route_registered')).to eq(native_vendor.fetch('route_registered'))
    expect(data.fetch('route_count')).to be_positive
    expect(data.fetch('source_sha256')).to eq(native_vendor.fetch('source_sha256'))
    data
  end

  def native_command(command, path, content)
    expect(file(path)).to include('exists' => false)
    generated = native('gadget', { command_base64: Base64.strict_encode64(command.b) }, 'native-gadget')
    expect(file(path)).to include('exists' => false)
    # The application redirects after decrypting a normal route string; our real
    # serialized object executes during destruction even if rendering then fails.
    http('/route/' + generated.fetch('value'))
    expect(file(path)).to eq('exists' => true, 'uid' => laravel_uid, 'base64' => Base64.strict_encode64(content.b))
  ensure
    rc_command('remove-native-proof', 'target', 'rm', '-f', '--', path)
    expect(file(path)).to include('exists' => false)
  end

  def native_login
    response = http('/login')
    expect(response.code).to eq('200')
    expect(response['X-APP-VERSION']).to eq(native_vendor.fetch('version'))
    uri = URI::HTTP.build(host: target_endpoint('target').fetch('host'), port: target_endpoint('target').fetch('port'), path: '/login')
    cookies = response.get_fields('set-cookie').flat_map { |header| HTTP::Cookie.parse(header, uri) }.to_h { |cookie| [cookie.name, cookie.value] }
    decoded = native('cookie', { name: 'XSRF-TOKEN', value: cookies.fetch('XSRF-TOKEN') }, 'native-xsrf')
    expect(decoded.fetch('prefix_valid')).to be(true)
    response
  end
end
