module Msf::DBManager::Service
  # Deletes a port and associated vulns matching this port
  def delete_service(opts)
    raise ArgumentError.new("The following options are required: :ids") if opts[:ids].nil?

  ::ApplicationRecord.connection_pool.with_connection {
    deleted = []
    opts[:ids].each do |service_id|
      service = Mdm::Service.find(service_id)
      begin
        deleted << service.destroy
      rescue
        elog("Forcibly deleting #{service.name}")
        deleted << service.delete
      end
    end

    return deleted
  }
  end

  # Iterates over the services table calling the supplied block with the
  # service instance of each entry.
  def each_service(wspace=framework.db.workspace, &block)
  ::ApplicationRecord.connection_pool.with_connection {
    wspace.services.each do |service|
      block.call(service)
    end
  }
  end

  def find_or_create_service(opts)
    report_service(opts)
  end

  #
  # Record a service in the database.
  #
  # opts MUST contain
  # +:host+::  the host where this service is running
  # +:port+::  the port where this service listens
  # +:proto+:: the transport layer protocol (e.g. tcp, udp)
  # +:workspace+:: the workspace for the service
  #
  # opts may contain
  # +:name+::  the application layer protocol (e.g. ssh, mssql, smb)
  # +:sname+:: an alias for the above
  # +:info+:: Detailed information about the service such as name and version information
  # +:state+:: The current listening state of the service (one of: open, closed, filtered, unknown)
  #
  def report_service(opts)
    report_services([opts]).first
  end

  def report_services(services)
    return if !active

    ::ApplicationRecord.connection_pool.with_connection { |conn|
      mdm_services = services.map do |opts|

        opts = opts.clone() # protect the original caller's opts
        addr  = opts.delete(:host) || return
        hname = opts.delete(:host_name)
        hmac  = opts.delete(:mac)
        host  = nil
        wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)
        opts.delete(:workspace) # this may not be needed however the service creation below might complain if missing
        hopts = {:workspace => wspace, :host => addr}
        hopts[:name] = hname if hname
        hopts[:mac]  = hmac  if hmac


        # Other report_* methods take :sname to mean the service name, so we
        # map it here to ensure it ends up in the right place despite not being
        # a real column.
        if opts[:sname]
          opts[:name] = opts.delete(:sname)
        end

        if addr.kind_of? ::Mdm::Host
          host = addr
          addr = host.address
        else
          host = report_host(hopts)
        end

        # TODO: This should be in the model, and already is?
        # if opts[:port].to_i.zero?
        #   dlog("Skipping port zero for service '%s' on host '%s'" % [opts[:name],host.address])
        #   return nil
        # end

        ret  = {}
  # =begin
  #     host = get_host(:workspace => wspace, :address => addr)
  #     if host
  #       host.updated_at = host.created_at
  #       host.state      = HostState::Alive
  #       host.save!
  #     end
  # =end

        proto = opts[:proto] || Msf::DBManager::DEFAULT_SERVICE_PROTO

        service = host.services.where(port: opts[:port].to_i, proto: proto).first_or_initialize
        ostate = service.state
        opts.each { |k,v|
          if (service.attribute_names.include?(k.to_s))
            service[k] = ((v and k == :name) ? v.to_s.downcase : v)
          elsif !v.blank?
            dlog("Unknown attribute for Service: #{k}")
          end
        }
        service.state ||= Msf::ServiceState::Open
        service.info  ||= ""

        begin
          framework.events.on_db_service(service) if service.new_record?
        rescue ::Exception => e
          wlog("Exception in on_db_service event handler: #{e.class}: #{e}")
          wlog("Call Stack\n#{e.backtrace.join("\n")}")
        end

        begin
          framework.events.on_db_service_state(service, service.port, ostate) if service.state != ostate
        rescue ::Exception => e
          wlog("Exception in on_db_service_state event handler: #{e.class}: #{e}")
          wlog("Call Stack\n#{e.backtrace.join("\n")}")
        end

        if (service and service.changed?)
          msf_import_timestamps(opts,service)
          service.validate!
        end

        # TODO: Why is this done manually, is this not default rails behavior
        if opts[:task]
          Mdm::TaskService.create(
            :task => opts[:task],
            :service => service
          )
        end

        service
      end

      #  TODO: Filter ids correctly
      new_serialized_services = []
      updated_serialized_services = []
      new_mdm_services = []
      updated_mdm_services = []
      mdm_services.each do |x|
        hash = x.serializable_hash
        if hash["id"].nil?
          hash.delete("id")
          new_mdm_services << x
          new_serialized_services << hash
          next
        end
        updated_mdm_services << x
        updated_serialized_services << hash
      end
      new_ids = []
      updated_ids = []
      new_ids = Mdm::Service.upsert_all(new_serialized_services) unless new_serialized_services.empty?
      updated_ids = Mdm::Service.upsert_all(updated_serialized_services) unless updated_serialized_services.empty?

      # Manually assign the bulk IDs, and run save callbacks
      new_mdm_services.zip(new_ids).each do |service, id|
        service.id = id
        service.changes_applied
        service.run_callbacks(:save) { true }
      end
      # Manually assign the bulk IDs, and run save callbacks
      updated_mdm_services.zip(updated_ids).each do |service, id|
        service.id = id
        service.changes_applied
        service.run_callbacks(:save) { true }
      end
    }
  end

  # Returns a list of all services in the database
  def services(opts)
    opts = opts.clone()
    search_term = opts.delete(:search_term)

    order_args = [:port]
    order_args.unshift(Mdm::Host.arel_table[:address]) if opts.key?(:hosts)

  ::ApplicationRecord.connection_pool.with_connection {
    # If we have the ID, there is no point in creating a complex query.
    if opts[:id] && !opts[:id].to_s.empty?
      return Array.wrap(Mdm::Service.find(opts[:id]))
    end

    opts = opts.clone() # protect the original caller's opts
    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)
    opts.delete(:workspace)

    if search_term && !search_term.empty?
      column_search_conditions = Msf::Util::DBManager.create_all_column_search_conditions(Mdm::Service, search_term)
      wspace.services.includes(:host).where(opts).where(column_search_conditions).order(*order_args)
    else
      wspace.services.includes(:host).where(opts).order(*order_args)
    end
  }
  end

  def update_service(opts)
    opts = opts.clone() # it is not polite to change arguments passed from callers
    opts.delete(:workspace) # Workspace isn't used with Mdm::Service. So strip it if it's present.

  ::ApplicationRecord.connection_pool.with_connection {
    id = opts.delete(:id)
    service = Mdm::Service.find(id)
    service.update!(opts)
    return service
  }
  end
end
