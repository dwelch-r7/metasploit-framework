module LoginDataProxy
  def logins(opts = {})
    begin
      self.data_service_operation do |data_service|
        data_service.logins(opts)
      end
    rescue => e
      self.log_error(e, "Problem retrieving logins")
    end
  end

  def create_credential_login(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.create_credential_login(opts)
      end
    rescue => e
      self.log_error(e, "Problem creating login")
    end
  end

  def update_login(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.update_login(opts)
      end
    rescue => e
      self.log_error(e, "Problem updating login")
    end
  end

  # Update cached logins for the attempted service and supplied credential fields.
  # Omitted identity fields remain unspecified; explicit nil and blank values
  # identify absent and blank credential components respectively.
  # @param opts [Hash] Credential identity, service, workspace and status options
  # @return [Object, nil] The first queried candidate core's cached logins, or nil
  # @raise [StandardError] If a data service operation fails
  def invalidate_login(opts)
    add_opts_workspace(opts)
    # Search for an existing Metasploit::Credential::Core object. It requires specific attributes.
    core_opts = {}
    core_opts[:workspace] = opts[:workspace]
    core_opts[:user] = opts.fetch(:username) if opts[:username]
    core_opts[:pass] = opts.fetch(:private_data) if opts[:private_data]
    core_opts[:ports] = [ opts.fetch(:port) ] if opts[:port]
    core_opts[:host_ranges] = [ opts.fetch(:address) ] if opts[:address]
    service_name = opts[:service_name]&.downcase
    core_opts[:svcs] = [service_name] if service_name

    # searching for cores and loading the array is a mitigation for
    # an issue seen with Rails 5 when calling first using a local database
    cores = creds(core_opts)
    cores = cores.to_a unless cores.is_a?(Array)
    return unless cores.first

    original_logins = cores.first.logins
    service_opts = { workspace: opts[:workspace] }
    service_opts[:hosts] = { address: opts[:address] } if opts[:address]
    service_opts[:port] = opts[:port] if opts[:port]
    service_opts[:proto] = opts[:protocol] if opts[:protocol]
    service_opts[:name] = service_name if service_name
    # Credential queries do not consistently scope hosts. Service IDs work
    # with both local associations and remotely returned cached login models.
    service_ids = Array(services(service_opts)).map(&:id)

    cores.each do |core|
      next unless invalidated_credential_matches?(core, opts)

      core.logins.each do |login|
        next unless service_ids.include?(login.service_id)

        login_opts = opts.slice(:access_level, :status, :last_attempted_at)
        login_opts[:id] = login.id
        update_login(login_opts)
      end
    end
    original_logins
  rescue StandardError => e
    log_error(e, 'Problem invalidating login')
  end

  private

  def invalidated_credential_matches?(core, opts)
    supplied = opts.slice(:username, :private_data, :private_type, :realm_key, :realm_value)
    supplied.all? do |key, value|
      stored = case key
               when :username then core.public&.username
               when :private_data then core.private&.data
               when :private_type
                 # Use Core#to_credential's STI mapping. BlankPassword is the
                 # Password subtype used by credential creation for blank data.
                 type = core.private&.type&.demodulize&.underscore
                 type == 'blank_password' && value.to_s == 'password' ? 'password' : type
               when :realm_key then core.realm&.key
               when :realm_value then core.realm&.value
               end
      value.nil? ? stored.nil? : !stored.nil? && stored.to_s.b == value.to_s.b
    end
  end
end
