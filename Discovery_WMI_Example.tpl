tpl 1.15 module Traversys.WMIExample;

metadata
    origin:= "Traversys";
    _name:= "WMI Example";
    tree_path:= "Custom", "Traversys", "WMI Example";
end metadata;

pattern WMIExample 1.0
    """ WMI Query Example """

    overview
        tags traversys, example;
    end overview;

    triggers
        on host := Host created, confirmed where os_type = "Windows";
    end triggers;

    body

        wmi_results := discovery.wmiQuery(host, 'select LastLogon, Name, UserType from Win32_NetworkLoginProfile', raw 'root\CIMV2');

        for result in wmi_results do
            if "LastLogon" in result then
                host.last_login := result.LastLogon;
                model.addDisplayAttribute(host, "last_login");
                break;
            end if;
        end for;

    end body;

end pattern;
