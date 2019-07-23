tpl 1.15 module Traversys.NetworkManager;

metadata
    origin:= "Traversys";
    _name:= "Network Manager";
    tree_path:= "Custom", "Traversys", "Network Manager";
end metadata;

identify NetworkManager 1.0
    tags network_manager;
    DiscoveredProcess cmd, args -> simple_identity;
    '/usr/sbin/NetworkManager', '--no-daemon' -> 'Network Manager';
end identify;
