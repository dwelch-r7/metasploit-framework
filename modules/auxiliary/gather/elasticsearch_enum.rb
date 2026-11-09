##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'csv'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Module::Deprecated

  moved_from 'auxiliary/scanner/elasticsearch/indices_enum'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Elasticsearch Enumeration Utility',
        'Description' => %q{
          This module enumerates Elasticsearch instances. It uses the REST API
          in order to gather information about the server, the cluster, nodes,
          in the cluster, indices, and pull data from those indices.
        },
        'Author' => [
          'Silas Cutler <Silas.Cutler[at]BlackListThisDomain.com>', # original indices enum module
          'h00die' # generic enum module
        ],
        'References' => [
          ['URL', 'https://www.elastic.co/guide/en/elasticsearch/reference/current/rest-apis.html']
        ],
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'SSL' => true,
          'RPORT' => 9200
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('USERNAME', [false, 'A specific username to authenticate as', '']),
        OptString.new('PASSWORD', [false, 'A specific password to authenticate as', '']),
        OptInt.new('DOWNLOADROWS', [true, 'Maximum number of rows to download per index', 5])
      ]
    )
  end

  def get_results(index)
    vprint_status("Downloading #{datastore['DOWNLOADROWS']} rows from index #{index}")
    body = { 'query' => { 'query_string' => { 'query' => '*' } }, 'size' => datastore['DOWNLOADROWS'], 'from' => 0, 'sort' => [] }
    request = {
      'uri' => normalize_uri(target_uri.path, index, '_search/'),
      'method' => 'POST',
      'headers' => {
        'Accept' => 'application/json'
      },
      'ctype' => 'application/json',
      'data' => body.to_json
    }
    request['authorization'] = basic_auth(datastore['USERNAME'], datastore['PASSWORD']) if datastore['USERNAME'] || datastore['PASSWORD']

    json_body = elasticsearch_response(send_request_cgi(request), operation: "download rows from index #{index}", expected_type: Hash, optional: true)
    return unless json_body

    result = json_body['hits']
    hits = result['hits'] if result.is_a?(Hash)
    unless hits.is_a?(Array) && hits.all? { |hit| hit.is_a?(Hash) && hit['_source'].is_a?(Hash) }
      vprint_error("Unable to download rows from index #{index}: The search response has no usable source documents")
      return
    end
    if hits.empty?
      vprint_status("No documents returned from index #{index}")
      return
    end

    columns = hits.first['_source'].keys
    # Table CSV output normalizes whitespace for display; extracted values must
    # retain their actual newlines, quotes and other literal text.
    data = CSV.generate(force_quotes: true) do |csv|
      csv << columns
      hits.each { |hit| csv << columns.map { |column| hit['_source'][column] } }
    end
    loot = store_loot('elasticserch.index.data', 'application/csv', rhost, data, "#{index}_data.csv", nil, @service)
    print_good("#{index} data stored to #{loot}")
  end

  def get_indices
    vprint_status('Querying indices...')
    request = {
      'uri' => normalize_uri(target_uri.path, '_cat', 'indices/'),
      'method' => 'GET',
      'headers' => {
        'Accept' => 'application/json'
      },
      'vars_get' => {
        # this is the query https://github.com/cars10/elasticvue uses for the chrome browser extension
        'h' => 'index,health,status,uuid,docs.count,store.size',
        'bytes' => 'mb'
      }
    }
    request['authorization'] = basic_auth(datastore['USERNAME'], datastore['PASSWORD']) if datastore['USERNAME'] || datastore['PASSWORD']

    json_body = elasticsearch_response(send_request_cgi(request), operation: 'query index information', expected_type: Array, optional: true)
    return unless json_body

    elastic_table = Rex::Text::Table.new(
      'Header' => 'Indicies Information',
      'Indent' => 2,
      'Columns' =>
      [
        'Name',
        'Health',
        'Status',
        'UUID',
        'Documents',
        'Storage Usage (MB)'
      ]
    )

    indices = []

    json_body.each do |index|
      next if datastore['VERBOSE'] == false && index['index'].starts_with?('.fleet')

      indices << index['index'] if index['docs.count'].to_i > 0 # avoid querying something with no data
      elastic_table << [
        index['index'],
        index['health'],
        index['status'],
        index['uuid'],
        index['docs.count'],
        "#{index['store.size']}MB"
      ]
      report_note(
        host: rhost,
        port: rport,
        proto: 'tcp',
        type: 'elasticsearch.index',
        data: { index: index['index'] },
        update: :unique_data
      )
    end

    print_good(elastic_table.to_s)
    indices.each do |index|
      get_results(index)
    end
  end

  def get_cluster_info
    vprint_status('Querying cluster information...')
    request = {
      'uri' => normalize_uri(target_uri.path, '_cluster', 'health'),
      'method' => 'GET'
    }
    request['authorization'] = basic_auth(datastore['USERNAME'], datastore['PASSWORD']) if datastore['USERNAME'] || datastore['PASSWORD']

    json_body = elasticsearch_response(send_request_cgi(request), operation: 'query cluster information', expected_type: Hash)

    elastic_table = Rex::Text::Table.new(
      'Header' => 'Cluster Information',
      'Indent' => 2,
      'Columns' =>
      [
        'Cluster Name',
        'Status',
        'Number of Nodes'
      ]
    )

    elastic_table << [
      json_body['cluster_name'],
      json_body['status'],
      json_body['number_of_nodes']
    ]
    print_good(elastic_table.to_s)
  end

  def get_node_info
    vprint_status('Querying node information...')
    request = {
      'uri' => normalize_uri(target_uri.path, '_cat', 'nodes'),
      'method' => 'GET',
      'headers' => {
        'Accept' => 'application/json'
      },
      'vars_get' => {
        'h' => 'ip,port,version,http,uptime,name,heap.current,heap.max,ram.current,ram.max,node.role,master,cpu,disk.used,disk.total'
      }
    }
    request['authorization'] = basic_auth(datastore['USERNAME'], datastore['PASSWORD']) if datastore['USERNAME'] || datastore['PASSWORD']

    json_body = elasticsearch_response(send_request_cgi(request), operation: 'query node information', expected_type: Array)

    elastic_table = Rex::Text::Table.new(
      'Header' => 'Node Information',
      'Indent' => 2,
      'Columns' =>
      [
        'IP',
        'Transport Port',
        'HTTP Port',
        'Version',
        'Name',
        'Uptime',
        'Ram Usage',
        'Node Role',
        'Master',
        'CPU Load',
        'Disk Usage'
      ]
    )
    json_body.each do |node|
      report_service(
        host: node['ip'],
        port: node['port'],
        proto: 'tcp',
        name: 'elasticsearch'
      )
      report_service(
        host: node['ip'],
        port: node['http'].split(':')[1],
        proto: 'tcp',
        name: 'elasticsearch'
      )
      elastic_table << [
        node['ip'],
        node['port'],
        node['http'],
        node['version'],
        node['name'],
        node['uptime'],
        "#{node['ram.current']}/#{node['ram.max']}",
        node['node.role'],
        node['master'],
        "#{node['cpu']}%",
        "#{node['disk.used']}/#{node['disk.total']}"
      ]
    end
    print_good(elastic_table.to_s)
  end

  def get_version_info
    vprint_status('Querying version information...')
    request = {
      'uri' => normalize_uri(target_uri.path),
      'method' => 'GET'
    }
    request['authorization'] = basic_auth(datastore['USERNAME'], datastore['PASSWORD']) if datastore['USERNAME'] || datastore['PASSWORD']

    json_body = elasticsearch_response(send_request_cgi(request), operation: 'query version information', expected_type: Hash)
    fail_with(Failure::UnexpectedReply, 'Elasticsearch cluster name not found, likely not Elasticsearch server') unless json_body['cluster_name']

    elastic_table = Rex::Text::Table.new(
      'Header' => 'Elastic Information',
      'Indent' => 2,
      'Columns' =>
      [
        'Name',
        'Cluster Name',
        'Version',
        'Build Type',
        'Lucene Version'
      ]
    )

    elastic_table << [
      json_body['name'],
      json_body['cluster_name'],
      json_body.dig('version', 'number'),
      json_body.dig('version', 'build_type'),
      json_body.dig('version', 'lucene_version'),
    ]
    print_good(elastic_table.to_s)

    @service = report_service(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: 'elasticsearch'
    )
  end

  def get_users
    vprint_status('Querying user information...')
    request = {
      'uri' => normalize_uri(target_uri.path, '_security', 'user/'),
      'method' => 'GET'
    }
    request['authorization'] = basic_auth(datastore['USERNAME'], datastore['PASSWORD']) if datastore['USERNAME'] || datastore['PASSWORD']

    json_body = elasticsearch_response(send_request_cgi(request), operation: 'query user information', expected_type: Hash, optional: true)
    unless json_body
      print_bad('Unable to pull user data')
      return
    end

    elastic_table = Rex::Text::Table.new(
      'Header' => 'User Information',
      'Indent' => 2,
      'Columns' =>
      [
        'Name',
        'Roles',
        'Email',
        'Metadata',
        'Enabled'
      ]
    )

    json_body.each do |username, attributes|
      elastic_table << [
        username,
        attributes['roles'],
        attributes['email'],
        attributes['metadata'],
        attributes['enabled'],
      ]
    end
    print_good(elastic_table.to_s)
  end

  # Optional collection failures preserve earlier results; discovery failures
  # must stop before a missing response reaches the remaining parsers.
  def elasticsearch_response(response, operation:, expected_type:, optional: false)
    unless response
      message = "Unable to #{operation}: The target did not respond"
      if optional
        vprint_error(message)
        return
      end

      fail_with(Failure::Unreachable, message)
    end
    fail_with(Failure::NoAccess, 'Credentials required, or incorrect') if response.code == 401
    if response.code == 403 && !optional
      fail_with(Failure::NoAccess, "Permission denied while attempting to #{operation} (HTTP 403)")
    end
    unless response.code == 200 && !response.body.to_s.empty?
      message = "Unable to #{operation}: Unexpected HTTP #{response.code} response"
      if optional
        vprint_error(message)
        return
      end

      fail_with(Failure::UnexpectedReply, message)
    end

    json = response.get_json_document
    return json if json.is_a?(expected_type) && !(json.is_a?(Hash) && json.empty?)

    shape = expected_type == Hash ? 'object' : 'array'
    message = "Unable to parse JSON while attempting to #{operation}: Expected a JSON #{shape}"
    if optional
      vprint_error(message)
      return
    end

    fail_with(Failure::UnexpectedReply, message)
  end

  def run
    get_version_info
    get_node_info
    get_cluster_info
    get_indices
    get_users
  end
end
