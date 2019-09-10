require "inspec/resources/command"
require "inspec/utils/convert"
require "inspec/utils/simpleconfig"

# copied directly from inspec-4.16.0/lib/inspec/resources/interface.rb
class ExtendedNetworkInterface < Inspec.resource(1)
  name "extended_interface"
  supports platform: "unix"
  desc "Extend the interface InSpec audit resource to test advanced network adapter properties"
  example <<~EXAMPLE
  describe interface('eth0') do
    it { should exist }
    it { should be_up }
    its('mac') { should eq '00:00:de:ad:be:ef' }
    its('mtu') { should eq '1420' }
    its('duplex') { should eq 'full'}
    its('flags') { should include 'NOARP' }
    its('static_arp') { should eq static_arp_entries[nic] }
    its('static_arp') { should eq eval('{"ip"=>"10.96.22.206", "mac"=>"00:1c:73:13:50:88"}') }
  end
  EXAMPLE

  def initialize(iface)
    @iface = iface

    @interface_provider = nil
    if inspec.os.linux?
      @interface_provider = LinuxInterface.new(inspec)
    else
      return skip_resource "The `interface` resource is not supported on your OS yet."
    end
  end

  def mac_address
    interface_info.nil? ? nil : interface_info[:mac_address]
  end

  def mtu
    interface_info.nil? ? nil : interface_info[:mtu]
  end

  def duplex
    interface_info.nil? ? nil : interface_info[:duplex]
  end

  def flags
    interface_info[:flags]
  end

  def static_arp
    interface_info[:static_arp]
  end

  def to_s
    "Interface #{@iface}"
  end

  private

  def interface_info
    return @cache if defined?(@cache)

    @cache = @interface_provider.interface_info(@iface) unless @interface_provider.nil?
  end
end

class InterfaceInfo
  include Converter
  attr_reader :inspec
  def initialize(inspec)
    @inspec = inspec
  end
end

class LinuxInterface < InterfaceInfo
  def interface_info(iface)
    # will return "[mtu]\n1500\n[type]\n1"
    cmd = inspec.command("find /sys/class/net/#{iface}/ -maxdepth 1 -type f -exec sh -c 'echo \"[$(basename {})]\"; cat {} || echo -n' \\;")
    return nil if cmd.exit_status.to_i != 0

    # parse values, we only recieve values, therefore we threat them as keys
    params = SimpleConfig.new(cmd.stdout.chomp).params

    # abort if we got an empty result-set
    return nil if params.empty?

    mac_address = nil
    if params.key?("address")
      mac_address, _value = params["address"].first
    end

    mtu = nil
    if params.key?("mtu")
      mtu, _value = params["mtu"].first
    end

    duplex = nil
    if params.key?("duplex")
      duplex, _value = params["duplex"].first
    end

    # Interface flags (SIOCGIFFLAGS) http://man7.org/linux/man-pages/man7/netdevice.7.html
    flags = []
    cmd = inspec.command("/sbin/ip -br link show dev #{iface}")
    return nil if cmd.exit_status.to_i != 0
    flags = cmd.stdout.chomp.split(/\s+/).last.gsub(/<|>/, '').split(',')

    #
    #[root@epcau-lab-srv004:~]# arp -a | grep PERM
    #? (10.96.22.222) at 00:1c:73:0f:80:c4 [ether] PERM on p7p4
    #? (10.96.22.206) at 00:1c:73:13:50:88 [ether] PERM on p7p3
    #
    static_arp = {}
    IO.popen('arp -a').readlines.select { |e| /PERM/.match(e) }.each { |line|
      line = line.split(' ')
      next if (line[7] != iface)
      static_arp = { 'ip' => line[1].gsub(/\(|\)/, ''), 'mac' => line[3] }
    }

    return {
      name: iface,
      mac_address: mac_address,
      mtu: mtu,
      duplex: duplex,
      flags: flags,
      static_arp: static_arp,
    }
  end
end
