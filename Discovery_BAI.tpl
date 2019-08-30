tpl 1.15 module Traversys_Discovery_BAI;

metadata
    origin:= "Traversys";
    _name:= "Discovery Deployment";
    tree_path:= "Custom", "Traversys", "Discovery Deployment";
end metadata;

table opMode 1.0
    "0"  -> "Normal";
    "1"  -> "Record";
    "2"  -> "Playback";
    default -> "Unknown";
end table;

pattern DiscoveryDeployment 1.0
    """
        This models the Discovery Deployment.

        Author: Traversys

        Change History
        --------------
        1.0 : Created

    """

    overview
        tags traversys, discovery_deployment;
    end overview;

    constants
        type := "Discovery Deployment";
        description := "BMC Discovery solution deployed for Traversys.";
        environment := "Test";
    end constants;

    triggers
        on si := SoftwareInstance created, confirmed where type = "BMC Discovery";
    end triggers;

    body

        host:= model.host(si);
        version := si.product_version;
        scan_mode := "Unknown";

        options:= discovery.runCommand(host, "/usr/tideway/bin/tw_options --user system --passwordfile /usr/tideway/.pass");

        if options and options.result then
            scan_op_mode := regex.extract(options.result, regex "DISCOVERY_OPERATING_MODE\s+=\s+(\d)", raw "\1");
            scan_mode := opMode[scan_op_mode];
            log.debug("Scan mode for %si.name%: %scan_mode%");
        end if;

        name := "%type% %version% (%environment%)";
        key := text.hash("%type%/%version%/%environment%");

        bai := model.BusinessApplicationInstance(key := key,
                                                 type := type,
                                                 name := name,
                                                 environment := environment,
                                                 version := version,
                                                 product_version := version,
                                                 description := description,
                                                 scanning_mode := scan_mode,
                                                 _traversys:= true
                                                );
        log.info("Business Application Instance created: %bai.name%");
        model.addDisplayAttribute(bai, [ "environment", "scanning_mode" ]);

        model.addContainment(bai, si);

        proxies := search(in si traverse Client:Communication:Server:SoftwareInstance);
        for proxy in proxies do
            model.addContainment(bai, proxy);
        end for;

    end body;

end pattern;
