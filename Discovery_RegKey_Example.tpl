tpl 1.15 module Traversys.RegKeyExample;

metadata
    origin:= "Traversys";
    _name:= "RegKey Example";
    tree_path:= "Custom", "Traversys", "RegKey Example";
end metadata;

pattern RegKeyExample 1.0
    """ Registry Query Example """

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

        reg_query := raw 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOwner';

        owner_key := discovery.registryKey(host, reg_query);

        host.registered_owner := owner_key.value;
        model.addDisplayAttribute(host, "registered_owner");

    end body;

end pattern;
