tpl 1.15 module Traversys.NetworkManager;

metadata
    origin:= "Traversys";
    _name:= "Network Manager";
    tree_path:= "Custom", "Traversys", "Network Manager";
end metadata;

pattern NetworkManager 1.2
    """
        This pattern models the Linux NetworkManager Instance.

        This pattern contains bugs!

        Author: Traversys

        Change History
        --------------
        1.0 : Created
        1.1 : Added SoftwareInstance and run Commands
        1.2 : Mistakes were made...

    """

    overview
        tags traversys, NetworkManager;
    end overview;

    constants
        type := "Network Manager (Debug Mode)";
    end constants;

    triggers
        on p := DiscoveredProcess where cmd matches unix_cmd "NetworkManager";
    end triggers;

    body

        host := model.host(p);
        hostname := host.name;

        packages:= model.findPackages(host, "Network Manager" );

        for package in packages do
            if "version" in package then
                version := package.version;
                log.debug("Package version found: %package.name% %package.version%");
                break;
            end if;
        end for;

        if version then
            name:= "%type% %version% on %hostname%";
            key:= hash("%hostname%/%type%/%version%");
        else
            name:= "%type% on %hostname%";
            key:= hash("%hostname%/%version%");
        end if;

        product_version:= regex.extract(version.result, regex "^(\d+(?:\.\d+)?)", raw "\1", no_match:= version.result);

        si:= model.SoftwareInstance(key:= key,
                                    type:= type,
                                    name:= name,
                                    version:= version,
                                    product_version:= product_version,
                                    _traversys:= true
                                    );
        log.info("Software Instance created: %si.name%");

        nmcli_cmd:= discovery.runCommand(host, "echo `/usr/bin/nmcli -t -f uuid c`");
        lspci_cmd:= discovery.runCommand(host, "/usr/sbin/lspci | grep -i 'ethernet'");

        if nmcli_cmd and nmcli_cmd.result then
            si.UUID := nmcli_cmd.result;
            log.debug("UUID found: %nmcli_cmd.result%");
            model.addDisplayAttribute(si, "uuid");
        end if;

        if lspci_cmd and lspci_cmd.result then
            si.eth_model := regex.extract(lspci_cmd.result,
                                          regex "Ethernet controller:\s(.*)\sGigabit",
                                          raw "\1",
                                          no_match := "Unknown");
            log.debug("Model found: %lspci_cmd.result%");
            model.addDisplayAttribute(si, "eth_model");
        end if;

    end body;

end pattern;

identify NetworkManager_simple_id 1.0
    tags network_manager;
    DiscoveredProcess cmd, args -> simple_identity;
    '/usr/sbin/NetworkManager', '--no-daemon' -> 'Network Manager';
end identify;
