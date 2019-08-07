tpl 1.15 module Traversys.forExample;

metadata
    origin:= "Traversys";
    _name:= "FOR Loop Example";
    tree_path:= "Custom", "Traversys", "FOR Loop Example";
end metadata;

pattern forExample 1.0
    """ FOR Loop Example """

    overview
        tags traversys, example;
    end overview;

    triggers
        on si := SoftwareInstance created, confirmed where type = "BMC Discovery";
    end triggers;

    body

    host:= model.host(si);
    failures := [];

    baseline := discovery.runCommand(host, "/usr/tideway/bin/tw_baseline --no-highlight");
    messages := regex.extractAll(baseline.result, regex ":\s(.*)\s\(\w+\)");
    highest := regex.extract(baseline.result, regex "Highest severity failure was (\w+)", raw "\1");

    log.info("Looping baseline failures...");
    for message in messages do
        if message matches regex "(INFO|MINOR|MAJOR|CRITICAL):\s" then
            list.append(failures, message);
            log.info("%message%");
        end if;
    end for;

    si.highest_baseline_failure := highest;
    si.baseline_failure_messages := failures;

    model.addDisplayAttribute(si, [ "highest_baseline_failure", "baseline_failure_messages" ] );

    end body;

end pattern;
