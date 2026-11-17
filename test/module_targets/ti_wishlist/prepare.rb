# frozen_string_literal: true

require_relative '../wordpress/plugin_sources'

WordpressPluginSources.prepare(directory: File.expand_path('../woocommerce', __dir__), cache_name: 'woocommerce')
WordpressPluginSources.prepare(directory: __dir__, cache_name: 'ti-wishlist')
