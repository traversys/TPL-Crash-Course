tpl 1.15 module Traversys.SearchExample;

metadata
    origin:= "Traversys";
    _name:= "Search Example";
    tree_path:= "Custom", "Traversys", "Search Example";
end metadata;

pattern SearchExample 1.0
    """ Search Example """

    overview
        tags traversys, example;
    end overview;

    triggers
        on si := SoftwareInstance created, confirmed where type = "BMC Discovery";
    end triggers;

    body

        host:= model.host(si);
        packages := search(in host traverse Host:HostedSoftware:InstalledSoftware:Package where name = "tw-python");
        package := packages[0];
        python_version:= "%package.version% %package.revision%";
        log.debug("Python Version found: %python_version%");

        si.python_version := python_version;
        model.addDisplayAttribute(si, "python_version");

    end body;

end pattern;
