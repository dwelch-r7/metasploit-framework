# frozen_string_literal: true

# Structural comparison for actual etcd v2 recursive documents.
module EtcdTarget
  # Native recursive reads leave directory children unordered. Preserve every
  # field and value while ordering only those child lists by their actual key.
  def self.canonical_document(value)
    case value
    when Hash
      value.to_h do |key, child|
        normalized = canonical_document(child)
        normalized = normalized.sort_by { |node| node.fetch('key') } if key == 'nodes'
        [key, normalized]
      end
    when Array
      value.map { |child| canonical_document(child) }
    else
      value
    end
  end
end
