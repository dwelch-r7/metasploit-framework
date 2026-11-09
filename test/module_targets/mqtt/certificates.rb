# frozen_string_literal: true

require 'fileutils'
require 'openssl'

# This key/certificate is generated only for the isolated public test broker.
# A fixed validity interval prevents cached image builds expiring between runs.
key = OpenSSL::PKey::RSA.new(2048)
certificate = OpenSSL::X509::Certificate.new
certificate.version = 2
certificate.serial = 1
certificate.subject = OpenSSL::X509::Name.parse('/CN=localhost')
certificate.issuer = certificate.subject
certificate.public_key = key.public_key
certificate.not_before = Time.utc(2020, 1, 1)
certificate.not_after = Time.utc(2100, 1, 1)
factory = OpenSSL::X509::ExtensionFactory.new
factory.subject_certificate = certificate
factory.issuer_certificate = certificate
certificate.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
certificate.add_extension(factory.create_extension('keyUsage', 'digitalSignature,keyEncipherment,keyCertSign', true))
certificate.add_extension(factory.create_extension('subjectAltName', 'DNS:localhost,DNS:tls,IP:127.0.0.1'))
certificate.sign(key, OpenSSL::Digest.new('SHA256'))
FileUtils.mkdir_p('/certificates')
File.write('/certificates/server.crt', certificate.to_pem)
File.write('/certificates/server.key', key.to_pem)
