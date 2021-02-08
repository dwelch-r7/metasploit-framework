# -*- coding: binary -*-
=begin

The Metasploit Rex library is provided under the 3-clause BSD license.

Copyright (c) 2005-2014, Rapid7, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this 
   list of conditions and the following disclaimer.
   
 * Redistributions in binary form must reproduce the above copyright notice, 
   this list of conditions and the following disclaimer in the documentation 
   and/or other materials provided with the distribution.
   
 * Neither the name of Rapid7, Inc. nor the names of its contributors may be 
   used to endorse or promote products derived from this software without 
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=end

module Rex
  Root = File.join(File.expand_path(File.dirname(__FILE__)), 'rex')
  LogSource = "rex"

  #
  # REX Gems
  #

  # Text manipulation library for things like generating random string
  autoload :Text, 'rex/text'
  # Library for Generating Randomized strings valid as Identifiers such as variable names
  autoload :RandomIdentifier, 'rex/random_identifier'
  # library for creating Powershell scripts for exploitation purposes
  autoload :Powershell, 'rex/powershell'
  # Library for processing and creating Zip compatible archives
  autoload :Zip, 'rex/zip'
  # Library for processing and creating tar compatible archives (not really a gem)
  autoload :Tar, 'rex/tar'
  # Library for parsing offline Windows Registry files
  autoload :Registry, 'rex/registry'
  # Library for parsing Java serialized streams
  autoload :Java, 'rex/java'
  # Library for creating C-style Structs
  autoload :Struct2,'rex/struct2'
  # Library for working with OLE
  autoload :OLE, 'rex/ole'
  # Library for creating and/or parsing MIME messages
  autoload :MIME, 'rex/mime'
  # Library for polymorphic encoders
  autoload :Encoder, 'rex/encoder'
  # Architecture subsystem
  autoload :Arch, 'rex/arch'
  # Exploit Helper Library
  autoload :Exploitation, 'rex/exploitation'

  # Generic classes

  autoload :Transformer, 'rex/transformer'
  autoload :File, 'rex/file'

  # Thread safety and synchronization
  autoload :Sync, 'rex/sync'
  autoload :ThreadSafe, 'rex/sync'
  autoload :Ref, 'rex/sync'
  autoload :ReadWriteLock, 'rex/sync'


  # Thread factory
  autoload :ThreadFactory, 'rex/thread_factory'


  # Assembly
  autoload :Assembly, 'rex/assembly/nasm'

  module IO
    # IO
    autoload :Stream, 'rex/io/stream'
    autoload :StreamAbstraction, 'rex/io/stream_abstraction'
    autoload :StreamServer, 'rex/io/stream_server'
  end
  # Sockets
  autoload :Socket, 'rex/socket'


  # Compatibility
  autoload :Compat, 'rex/compat'

  module SSLScan
    # SSLScan
    autoload :Scanner, 'rex/sslscan/scanner'
    autoload :Result, 'rex/sslscan/result'
  end
end

# Overload the Kernel.sleep() function to be thread-safe
Kernel.class_eval("
  def sleep(seconds=nil)
    Rex::ThreadSafe.sleep(seconds)
  end
")

# Overload the Kernel.select function to be thread-safe
Kernel.class_eval("
  def select(rfd = nil, wfd = nil, efd = nil, to = nil)
    Rex::ThreadSafe.select(rfd, wfd, efd, to)
  end
")
