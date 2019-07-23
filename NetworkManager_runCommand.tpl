tpl 1.15 module Traversys.NetworkManager;

metadata
    origin:= "Traversys";
    _name:= "Network Manager";
    tree_path:= "Custom", "Traversys", "Network Manager";
end metadata;

pattern NetworkManager 1.0
    """ Network Manager runCommand Example """

    overview
        tags traversys, example;
    end overview;

    triggers
        on p := DiscoveredProcess where cmd matches unix_cmd "NetworkManager";
    end triggers;

    body

        host := model.host(p);
        hostname := host.name;
        version := discovery.runCommand(host, "/usr/tideway/bin/tw_baseline -v");
        log.debug("Run command output from %hostname%: %version.result%, duration: %version.discovery_duration%");

    end body;

end pattern;

identify NetworkManager_simple_id 1.0
    tags network_manager;
    DiscoveredProcess cmd, args -> simple_identity;
    '/usr/sbin/NetworkManager', '--no-daemon' -> 'Network Manager';
end identify;
