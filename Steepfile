target :libraries do
  disable_collection
  library 'pathname'
  signature 'typing'
  check 'lib/rex/ntpath.rb'
  check 'lib/rex/version.rb'
  check 'lib/rex/proto/dcerpc/uuid.rb'
  check 'lib/rex/proto/dcerpc/packet.rb'
  check 'lib/rex/proto/ms_tds/ms_tds_login7_password.rb'
  check 'lib/msf/core/exploit/retry.rb'
  configure_code_diagnostics Steep::Diagnostic::Ruby.strict
  configure_code_diagnostics do |diagnostics|
    diagnostics[Steep::Diagnostic::Ruby::FallbackAny] = :error
    diagnostics[Steep::Diagnostic::Ruby::UnexpectedError] = :error
    diagnostics[Steep::Diagnostic::Ruby::UnsupportedSyntax] = :error
    diagnostics[Steep::Diagnostic::Ruby::SyntaxError] = :error
    diagnostics[Steep::Diagnostic::Ruby::RBSError] = :error
    diagnostics[Steep::Diagnostic::Ruby::MethodDefinitionMissing] = :error
  end

  group :ini do
    check 'lib/rex/parser/ini.rb'
    configure_code_diagnostics do |diagnostics|
      # Steep does not recognize this legacy class's attr_reader/writer and alias
      # implementations. Their runtime contracts are covered by its focused specs.
      diagnostics[Steep::Diagnostic::Ruby::MethodDefinitionMissing] = :hint
    end
  end
end
