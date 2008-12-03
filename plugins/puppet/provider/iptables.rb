require 'puppet'

Puppet::Type.type(:iptables).provide :iptables do
    desc "I intented to use 'ensure' as a parameter, not a property, however
          that does not seem to be possible. Thus provider is needed."

    def ensure
      @resource.value(:ensure)
    end
end
