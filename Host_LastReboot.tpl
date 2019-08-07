tpl 1.15 module Traversys.LastReboot;

metadata
    origin:= "Traversys";
    _name:= "Last Reboot";
    tree_path:= "Custom", "Traversys", "Last Reboot";
end metadata;

pattern LastReboot 1.0
    """ Last Reboot Example """

    overview
        tags traversys, example;
    end overview;

    triggers
        on host := Host created, confirmed where host_type = "UNIX Server";
    end triggers;

    body

        hostname := host.name;
        lastBootCmd := discovery.runCommand(host, "who -b");
        log.debug("Host %hostname% was last rebooted: %lastBootCmd.result%");
        host.last_reboot := regex.extract(lastBootCmd.result, regex "(\d+-\d+-\d+)", raw "\1");
        model.addDisplayAttribute(host, "last_reboot");

    end body;

end pattern;
