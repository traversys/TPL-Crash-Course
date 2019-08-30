tpl 1.15 module Traversys_DiscoverySupport;

metadata
    origin:= "Traversys";
    _name:= "Discovery Support";
    tree_path:= "Custom", "Traversys", "Discovery Support";
end metadata;

table DiscoSupport 1.0
    "11.3"  -> "March 21, 2023";
    "11.2"  -> "September 15, 2022";
    "11.1"  -> "March 3, 2021";
    "11.0"  -> "March 3, 2021";
    "10.2"  -> "EOL";
    "10.1"  -> "EOL";
    "10.0"  -> "EOL";
    "9.0"   -> "EOL";
    default -> none;
end table;

table DiscoRelease 1.0
    "11.3.05" -> "May 03, 2019";
    "11.3.04" -> "November 29, 2018";
    "11.3.03" -> "October 30, 2018";
    "11.3.02" -> "July 11, 2018";
    "11.3.01" -> "June 22, 2018";
    "11.3"    -> "March 21, 2018";
    default   -> none;
end table;

definitions support 1.0
    """ Support Functions """

    define getDate(si, result, tableName, display) -> dateValue
        """ Checks Discovery version and returns a date """

        version := regex.extract(result, regex "Version:\s((\d+\.?)+)\sRelease", raw "\1");
        dateValue := tableName[version];
        model.addDisplayAttribute(si, display);

        return dateValue;

    end define;

end definitions;

pattern DiscoverySupport 1.0
    """ Support Table Example """

    overview
        tags traversys, example;
    end overview;

    triggers
        on si := SoftwareInstance created, confirmed where type = "BMC Discovery";
    end triggers;

    body

        host:= model.host(si);
        baseline:= discovery.runCommand(host, "/usr/tideway/bin/tw_baseline -v");
        if baseline and baseline.result then
            si.end_of_life := support.getDate(si, baseline.result, DiscoSupport, "end_of_life");
            si.release_date := support.getDate(si, baseline.result, DiscoRelease, "release_date");
        end if;

    end body;

end pattern;
