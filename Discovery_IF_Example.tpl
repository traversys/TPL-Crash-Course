tpl 1.15 module Traversys.ifExample;

metadata
    origin:= "Traversys";
    _name:= "IF Condition Example";
    tree_path:= "Custom", "Traversys", "IF Condition Example";
end metadata;

pattern ifExample 1.0
    """ IF Condition Example """

    overview
        tags traversys, example;
    end overview;

    triggers
        on si := SoftwareInstance created, confirmed where type = "BMC Discovery";
    end triggers;

    body

    host:= model.host(si);
    if si.scanning_appliance = true then
        runCMD:= discovery.runCommand(host, "ls /usr/tideway/etc/ca/consolidator_* 2> /dev/null");
        if runCMD and runCMD.result then
            si.consolidation:= true;
        else
            si.consolidation:= false;
        end if;

        model.addDisplayAttribute(si, "consolidation");
        
    end if;

    end body;

end pattern;
